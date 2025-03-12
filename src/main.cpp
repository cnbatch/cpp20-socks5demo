#include <cstdio>
#include <iostream>
#include <array>
#include <span>
#include <optional>
#include <asio.hpp>

using asio::ip::tcp;
using asio::ip::udp;
using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable_t;
using tcp_acceptor = use_awaitable_t<>::as_default_on_t<tcp::acceptor>;
using tcp_socket = use_awaitable_t<>::as_default_on_t<tcp::socket>;
using udp_socket = use_awaitable_t<>::as_default_on_t<udp::socket>;
namespace this_coro = asio::this_coro;

constexpr uint8_t socks_version = 0x05;

// SOCKS5 Method Codes
constexpr uint8_t socks_method_no_auth = 0;
constexpr uint8_t socks_method_gssapi = 0x01;
constexpr uint8_t socks_method_user_pwd = 0x02;
constexpr uint8_t socks_method_unacceptable = 0xFF;

// SOCKS5 Command Codes
constexpr uint8_t socks_cmd_connect = 0x01;
constexpr uint8_t socks_cmd_bind = 0x02;
constexpr uint8_t socks_cmd_udp_associate = 0x03;

// Address Types
constexpr uint8_t socks_atyp_ipv4 = 0x01;
constexpr uint8_t socks_atyp_domain = 0x03;
constexpr uint8_t socks_atyp_ipv6 = 0x04;

// SOCKS5 Reply Codes
constexpr uint8_t socks_reply_success = 0x00;
constexpr uint8_t socks_reply_general_failure = 0x01;
constexpr uint8_t socks_reply_connection_not_allowed = 0x02;
constexpr uint8_t socks_reply_network_unreachable = 0x03;
constexpr uint8_t socks_reply_host_unreachable = 0x04;
constexpr uint8_t socks_reply_connection_refused = 0x05;
constexpr uint8_t socks_reply_ttl_expired = 0x06;
constexpr uint8_t socks_reply_command_not_supported = 0x07;
constexpr uint8_t socks_reply_address_type_not_supported = 0x08;

constexpr unsigned int socks_header_ipv4_size = 10;
constexpr unsigned int socks_header_ipv6_size = 22;

constexpr auto expire_seconds = std::chrono::seconds(180);

#ifdef __linux__	
constexpr bool linux_system = true;
#else
constexpr bool linux_system = false;
#endif

uint8_t convert_error_code(asio::error_code ec);

#pragma pack (push, 1)
struct socks5_udp_packet_header
{
	uint16_t rsv;
	uint8_t frag;
	uint8_t address_type;
};

struct socks5_udp_packet_ipv4
{
	uint16_t rsv;
	uint8_t frag;
	uint8_t address_type;
	uint8_t dst_addr[4];
	uint16_t dst_port;
	uint8_t data[1];
};

struct socks5_udp_packet_ipv6
{
	uint16_t rsv;
	uint8_t frag;
	uint8_t address_type;
	uint8_t dst_addr[16];
	uint16_t dst_port;
	uint8_t data[1];
};
#pragma pack(pop)

std::shared_ptr<asio::ip::address> tcp_local_address;

class tcp_session : public std::enable_shared_from_this<tcp_session>
{
public:
	tcp_session(tcp_socket local_socket, tcp_socket remote_socket) :
		local_socket(std::move(local_socket)), remote_socket(std::move(remote_socket)) {}

	void start()
	{
		co_spawn(local_socket.get_executor(),
			[self = shared_from_this()] { return self->reader(); },
			detached);

		co_spawn(local_socket.get_executor(),
			[self = shared_from_this()] { return self->writer(); },
			detached);
	}

private:
	awaitable<void> reader()
	{
		std::array<uint8_t, 4096> data = {};
		asio::error_code ec;
		while (true)
		{
			size_t n = co_await local_socket.async_read_some(asio::buffer(data), asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
			{
				stop();
				break;
			}

			if (n == 0)
				continue;

			co_await remote_socket.async_write_some(asio::buffer(data, n), asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
			{
				stop();
				break;
			}
		}
	}

	awaitable<void> writer()
	{
		std::array<uint8_t, 4096> data = {};
		asio::error_code ec;
		while (true)
		{
			size_t n = co_await remote_socket.async_read_some(asio::buffer(data), asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
			{
				stop();
				break;
			}

			if (n == 0)
				continue;

			co_await local_socket.async_write_some(asio::buffer(data, n), asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
			{
				stop();
				break;
			}
		}
	}

	void stop()
	{
		asio::error_code ec;
		local_socket.close(ec);
		remote_socket.close(ec);
	}

	tcp_socket local_socket;
	tcp_socket remote_socket;
};

class tcp_binding : public std::enable_shared_from_this<tcp_binding>
{
public:
	tcp_binding(tcp_socket client_socket, tcp_acceptor acceptor) :
		timer(client_socket.get_executor()), client_socket(std::move(client_socket)), acceptor(std::move(acceptor)){};

	void start(std::array<uint8_t, 32> reply)
	{
		co_spawn(client_socket.get_executor(),
			[self = shared_from_this()] { return self->watchdog(); },
			detached);
		co_spawn(client_socket.get_executor(),
			[self = shared_from_this(), reply] { return self->handle_bind_request(reply); },
			detached);
	}
private:
	awaitable<void> watchdog()
	{
		asio::error_code ec;
		auto now = std::chrono::steady_clock::now();
		std::chrono::steady_clock::time_point deadline = now + expire_seconds;
		while (deadline > now)
		{
			timer.expires_at(deadline);
			co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
				co_return;
			now = std::chrono::steady_clock::now();
		}
		ec.clear();
		acceptor.cancel(ec);
	}

	awaitable<void> handle_bind_request(std::array<uint8_t, 32> reply)
	{
		asio::error_code ec;
		try
		{
			unsigned int reply_size = 0;
			tcp_socket listener_socket = co_await acceptor.async_accept(asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
			{
				reply[1] = convert_error_code(ec);
				co_await client_socket.async_write_some(asio::buffer(reply, reply_size));
				co_return;
			}

			tcp::endpoint remote_endpoint = listener_socket.remote_endpoint();
			asio::ip::address remote_address = remote_endpoint.address();
			uint16_t remote_port = remote_endpoint.port();
			if (remote_address.is_v6())
			{
				reply_size = socks_header_ipv6_size;
				reply[3] = socks_atyp_ipv6;
				asio::ip::address_v6::bytes_type v6_bytes = remote_address.to_v6().to_bytes();
				std::copy(v6_bytes.begin(), v6_bytes.end(), reply.begin() + 4);
				*(uint16_t *)(reply.data() + 20) = htons(remote_port);

			}
			else
			{
				reply_size = socks_header_ipv4_size;
				reply[3] = socks_atyp_ipv4;
				asio::ip::address_v4::bytes_type v4_bytes = remote_address.to_v4().to_bytes();
				*(uint32_t *)(reply.data() + 4) = *(uint32_t *)v4_bytes.data();
				*(uint16_t *)(reply.data() + 8) = htons(remote_port);
			}

			// BIND: Second Reply
			co_await client_socket.async_write_some(asio::buffer(reply, reply_size));

			// 5. Forward Traffic
			std::make_shared<tcp_session>(std::move(client_socket), std::move(listener_socket))->start();
		}
		catch (std::exception &e)
		{
			std::printf("TCP BIND Exception: %s\n", e.what());
		}
		ec.clear();
		timer.cancel(ec);
	}

	asio::steady_timer timer;
	tcp_socket client_socket;
	tcp_acceptor acceptor;
};

class udp_session : public std::enable_shared_from_this<udp_session>
{
public:
	udp_session(tcp_socket request_socket, udp_socket listener_socket) :
		request_socket(std::move(request_socket)), listener_socket(std::move(listener_socket)),
		forwarder_socket(listener_socket.get_executor(), udp::endpoint()) {}

	void start()
	{
		co_spawn(request_socket.get_executor(),
			[self = shared_from_this()] { return self->reader(); },
			detached);

		co_spawn(request_socket.get_executor(),
			[self = shared_from_this()] { return self->writer(); },
			detached);
	}

private:
	awaitable<void> reader()
	{
		std::array<uint8_t, 4096> data = {};
		udp::endpoint from_udp_endpoint;

		while(request_socket.is_open())
		{
			asio::error_code ec;
			std::string hostname;
			uint16_t port = 0;
			size_t bytes_read = co_await listener_socket.async_receive_from(asio::buffer(data), from_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
				break;
			if (bytes_read <= 4)
				continue;
			client_udp_endpoint = from_udp_endpoint;

			std::unique_ptr<udp::endpoint> remote_udp_endpoint;
			std::span<uint8_t> client_data = {};
			socks5_udp_packet_header *udp_raw_data = (socks5_udp_packet_header *)data.data();
			if (udp_raw_data->frag) // Too cumbersome to implement
				continue;

			switch (udp_raw_data->address_type)
			{
			case socks_atyp_ipv4:
			{
				if (bytes_read <= socks_header_ipv4_size)
					continue;

				socks5_udp_packet_ipv4 *udp_v4_raw_data = (socks5_udp_packet_ipv4 *)data.data();
				asio::ip::address_v4::bytes_type address_bytes;
				*(uint32_t *)address_bytes.data() = *(uint32_t *)udp_v4_raw_data->dst_addr;
				asio::ip::address_v4 address(address_bytes);
				uint16_t port = ntohs(udp_v4_raw_data->dst_port);
				remote_udp_endpoint = std::make_unique<udp::endpoint>(address, port);
				client_data = std::span<uint8_t>((uint8_t *)udp_v4_raw_data->data, data.data() + bytes_read);	// extract client data from UDP Packet
				break;
			}
			case socks_atyp_ipv6:
			{
				if (bytes_read <= socks_header_ipv6_size)
					continue;
		
				socks5_udp_packet_ipv6 *udp_v6_raw_data = (socks5_udp_packet_ipv6 *)data.data();
				asio::ip::address_v6::bytes_type address_bytes;
				std::copy(std::begin(udp_v6_raw_data->dst_addr), std::end(udp_v6_raw_data->dst_addr), address_bytes.begin());
				asio::ip::address_v6 address(address_bytes);
				uint16_t port = ntohs(udp_v6_raw_data->dst_port);
				remote_udp_endpoint = std::make_unique<udp::endpoint>(address, port);
				client_data = std::span<uint8_t>((uint8_t *)udp_v6_raw_data->data, data.data() + bytes_read);	// extract client data from UDP Packet
				break;
			}
			case socks_atyp_domain:
			{
				if (bytes_read <= socks_header_ipv4_size)
					continue;

				size_t domain_length = data[4];
				constexpr size_t header_size = sizeof(socks5_udp_packet_header);
				if (bytes_read <= header_size + 1 + domain_length + 2)
					continue;

				uint8_t *domain_ptr_starts = &data[5];
				uint8_t *port_ptr_starts = domain_ptr_starts + domain_length;
				hostname = std::string(domain_ptr_starts, domain_ptr_starts + domain_length);
				port = ntohs(*(uint16_t *)port_ptr_starts);

				udp::resolver resolver(request_socket.get_executor());
				udp::resolver::results_type endpoints = co_await resolver.async_resolve(hostname, std::to_string(port), asio::redirect_error(asio::use_awaitable, ec));
				if (ec || endpoints.empty())
					continue;

				// starting from ASIO 1.31, the endpoints can be connected directly:
				// udp::endpoint connected_endpoint = co_await asio::async_connect(forwarder_socket, endpoints, asio::redirect_error(asio::use_awaitable, ec));
				for (auto &&endpoint : endpoints)
				{
					co_await forwarder_socket.async_connect(endpoint, asio::redirect_error(asio::use_awaitable, ec));
					if (!ec)
					{
						remote_udp_endpoint = std::make_unique<udp::endpoint>(endpoint.endpoint());
						break;
					}
				}

				if (ec)
					continue;

				uint8_t *client_data_ptr_starts = port_ptr_starts + 2;
				client_data = std::span<uint8_t>(client_data_ptr_starts, data.data() + bytes_read);	// extract client data from UDP Packet

				break;
			}
			default:
				continue;
			}

			if (remote_udp_endpoint == nullptr)
				continue;

			co_await forwarder_socket.async_send_to(asio::buffer(client_data.data(), client_data.size()), *remote_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
		}
		stop();
	}

	awaitable<void> writer()
	{
		std::array<uint8_t, 4096> data = {};

		while (request_socket.is_open())
		{
			udp::endpoint remote_udp_endpoint;
			asio::error_code ec;
			size_t bytes_read = co_await forwarder_socket.async_receive_from(asio::buffer(data), remote_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
				break;

			std::array<uint8_t, 32> socks5_header_raw = {};
			size_t header_size = 0;
			asio::ip::address remote_address = remote_udp_endpoint.address();
			uint16_t port = remote_udp_endpoint.port();
			if (remote_address.is_v4())
			{
				socks5_udp_packet_ipv4 *socks5_header = (socks5_udp_packet_ipv4 *)socks5_header_raw.data();
				socks5_header->address_type = socks_atyp_ipv4;
				header_size = socks_header_ipv4_size;

				asio::ip::address_v4::bytes_type v4_bytes = remote_address.to_v4().to_bytes();
				*(uint32_t *)socks5_header->dst_addr = *(uint32_t *)v4_bytes.data();
				socks5_header->dst_port = htons(port);

			}
			else if (remote_address.is_v6())
			{
				socks5_udp_packet_ipv6 *socks5_header = (socks5_udp_packet_ipv6 *)socks5_header_raw.data();
				socks5_header->address_type = socks_atyp_ipv4;
				header_size = socks_header_ipv6_size;

				asio::ip::address_v6::bytes_type v6_bytes = remote_address.to_v6().to_bytes();
				std::copy(v6_bytes.begin(), v6_bytes.end(), std::begin(socks5_header->dst_addr));
				socks5_header->dst_port = htons(port);
			}
			else continue;

			std::array<asio::const_buffer, 2> reply_buffers = 
			{
				asio::buffer(socks5_header_raw.data(), header_size),
				asio::buffer(data.data(), bytes_read)
			};
			co_await listener_socket.async_send_to(reply_buffers, client_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
		}
		stop();
	}

	void stop()
	{
		asio::error_code ec;
		request_socket.close(ec);
		listener_socket.close(ec);
	}

	tcp_socket request_socket;
	udp_socket listener_socket;
	udp_socket forwarder_socket;
	udp::endpoint client_udp_endpoint;
};


uint8_t convert_error_code(asio::error_code ec)
{
	uint8_t reply_code = 0;
	switch (ec.value())
	{
	case asio::error::access_denied:
		reply_code = socks_reply_connection_not_allowed;
		break;
	case asio::error::network_unreachable:
		[[fallthrough]];
	case asio::error::network_reset:
		[[fallthrough]];
	case asio::error::network_down:
		reply_code = socks_reply_network_unreachable;
		break;
	case asio::error::host_not_found:
		[[fallthrough]];
	case asio::error::host_not_found_try_again:
		reply_code = socks_reply_host_unreachable;
		break;
	case asio::error::connection_aborted:
		[[fallthrough]];
	case asio::error::connection_reset:
		[[fallthrough]];
	case asio::error::connection_refused:
		reply_code = socks_reply_connection_refused;
		break;
	case asio::error::timed_out:
		reply_code = socks_reply_ttl_expired;
		break;
	case asio::error::address_family_not_supported:
		reply_code = socks_reply_address_type_not_supported;
		break;
	default:
		reply_code = socks_reply_general_failure;
		break;
	}
	return reply_code;
}

awaitable<void> socks5_access(tcp_socket client_socket, const char *username, const char *password)
{
	try
	{
		std::array<uint8_t, 1024> data = {};
		// 1. Negotiation
		size_t bytes_read = co_await asio::async_read(client_socket, asio::buffer(data), asio::transfer_exactly(2), asio::use_awaitable);
		if (bytes_read != 2 || data[0] != socks_version)
			co_return;

		uint8_t num_methods = data[1];
		bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, num_methods), asio::transfer_exactly(num_methods), asio::use_awaitable);
		if (bytes_read != num_methods)
			co_return;

		std::optional<uint8_t> method_supported;
		for (uint16_t i = 0; i < num_methods; i++)
		{
			if (data[i] == socks_method_no_auth && username == nullptr && password == nullptr)
			{
				method_supported = data[i];
				break;
			}

			if (data[i] == socks_method_user_pwd && username && password)
			{
				method_supported = data[i];
				break;
			}
		}

		uint8_t chosen_method = method_supported.has_value() ? method_supported.value() : socks_method_unacceptable;
		data[0] = socks_version;
		data[1] = chosen_method;

		co_await asio::async_write(client_socket, asio::buffer(data, 2));
		if (!method_supported)
		{
			std::cerr << "No supported authentication method." << std::endl;
			co_return;
		}

		// 2. Username / Password Authentication
		if (chosen_method == socks_method_user_pwd)
		{
			std::string recv_username, recv_password;
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 1), asio::transfer_exactly(1), asio::use_awaitable);
			if (bytes_read != 1 || data[0] != 1)
			{
				std::cerr << "Invalid SOCKS version or message length incorrect." << std::endl;
				co_return;
			}
			
			// Length of Username
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 1), asio::transfer_exactly(1), asio::use_awaitable);
			if (bytes_read != 1)
				co_return;
			uint8_t username_length = data[0];
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, username_length), asio::transfer_exactly(username_length), asio::use_awaitable);
			if (bytes_read != username_length)
				co_return;
			recv_username = std::string(data.data(), data.data() + username_length);

			// Length of Password
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 1), asio::transfer_exactly(1), asio::use_awaitable);
			if (bytes_read != 1)
				co_return;
			uint8_t password_length = data[0];
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, password_length), asio::transfer_exactly(password_length), asio::use_awaitable);
			if (bytes_read != password_length)
				co_return;
			recv_password = std::string(data.data(), data.data() + password_length);

			data[0] = 1;
			if (recv_username == username && recv_password == password)
			{
				data[1] = 0;
				co_await asio::async_write(client_socket, asio::buffer(data, 2));
			}
			else
			{
				data[1] = 1;
				co_await asio::async_write(client_socket, asio::buffer(data, 2));
				co_return;
			}
		}

		// 3. Request
		bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 4), asio::transfer_exactly(4), asio::use_awaitable);
		if (bytes_read != 4 || data[0] != socks_version)
		{
			std::cerr << "Invalid SOCKS version or message too short." << std::endl;
			co_return;
		}

		std::array<uint8_t, 32> reply = {};
		unsigned int reply_size = 0;
		uint8_t command = data[1];
		uint8_t address_type = data[3];
		std::unique_ptr<tcp::endpoint> tcp_endpoint;
		std::string hostname;
		uint16_t port = 0;

		reply[0] = socks_version;

		switch (address_type)
		{
		case socks_atyp_ipv4:
		{
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 4), asio::transfer_exactly(4), asio::use_awaitable);
			if (bytes_read != 4)
			{
				std::cerr << "Error reading IPv4 address." << std::endl;
				co_return;
			}
			asio::ip::address_v4::bytes_type address_bytes;
			*(uint32_t *)address_bytes.data() = *(uint32_t *)data.data();
			asio::ip::address_v4 address(address_bytes);
			tcp_endpoint = std::make_unique<tcp::endpoint>(address, 0);
			break;
		}
		case socks_atyp_domain:
		{
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 1), asio::transfer_exactly(1), asio::use_awaitable);
			if (bytes_read != 1)
			{
				std::cerr << "Error reading domain length." << std::endl;
				co_return;
			}
			size_t domain_length = data[0];
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, domain_length), asio::transfer_exactly(domain_length), asio::use_awaitable);
			if (bytes_read != domain_length)
			{
				std::cerr << "Error reading domain name." << std::endl;
				co_return;
			}
			hostname = std::string(data.begin(), data.begin() + domain_length);
			break;
		}
		case socks_atyp_ipv6:
		{
			bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 16), asio::transfer_exactly(16), asio::use_awaitable);
			if (bytes_read != 16)
			{
				std::cerr << "Error reading IPv6 address." << std::endl;
				co_return;
			}
			asio::ip::address_v6::bytes_type address_bytes;
			std::copy_n(data.begin(), 16, address_bytes.begin());
			asio::ip::address_v6 address(address_bytes);
			tcp_endpoint = std::make_unique<tcp::endpoint>(address, 0);
			break;
		}
		default:
			// Send "Address type not supported" reply
			std::cerr << "Unsupported address type: " << static_cast<uint16_t>(address_type) << std::endl;
			reply_size = socks_header_ipv4_size;
			reply[1] = socks_reply_address_type_not_supported;
			reply[3] = socks_atyp_ipv4;
			co_await asio::async_write(client_socket, asio::buffer(reply, reply_size));
			co_return;
		}

		// Read port number
		bytes_read = co_await asio::async_read(client_socket, asio::buffer(data, 2), asio::transfer_exactly(2), asio::use_awaitable);
		if (bytes_read != 2)
		{
			std::cerr << "Error reading port number." << std::endl;
			co_return;
		}
		port = ntohs(*((uint16_t *)data.data()));
		if (tcp_endpoint != nullptr)
			tcp_endpoint->port(port);

		// 4. Establish Connection
		switch (command)
		{
		case socks_cmd_connect:
		{
			asio::error_code ec;
			reply[1] = socks_reply_success;
			if (address_type == socks_atyp_ipv6)
			{
				reply_size = socks_header_ipv6_size;
				reply[3] = socks_atyp_ipv6;
			}
			else
			{
				reply_size = socks_header_ipv4_size;
				reply[3] = socks_atyp_ipv4;
			}
			
			tcp_socket remote_socket(client_socket.get_executor());
			if (tcp_endpoint == nullptr)
			{
				tcp::resolver resolver(client_socket.get_executor());
				tcp::resolver::results_type endpoints = co_await resolver.async_resolve(hostname, std::to_string(port), asio::redirect_error(asio::use_awaitable, ec));
				if (endpoints.empty() || ec)
				{
					if (ec)
						reply[1] = convert_error_code(ec);
					if (endpoints.empty())
						reply[1] = socks_reply_network_unreachable;
					// 4. Send Reply
					co_await client_socket.async_write_some(asio::buffer(reply, reply_size));
					break;
				}

				// starting from ASIO 1.31, the endpoints can be connected directly:
				// tcp::endpoint connected_endpoint = co_await asio::async_connect(remote_socket, endpoints, asio::redirect_error(asio::use_awaitable, ec));
				for (auto &&endpoint : endpoints)
				{
					co_await remote_socket.async_connect(endpoint, asio::redirect_error(asio::use_awaitable, ec));
					if (!ec)
					{
						tcp_endpoint = std::make_unique<tcp::endpoint>(endpoint.endpoint());
						break;
					}
				}
			}

			if (ec || tcp_endpoint == nullptr)
			{
				if (ec)
					reply[1] = convert_error_code(ec);
				else
					reply[1] = socks_reply_network_unreachable;
				// 5. Send Reply
				co_await client_socket.async_write_some(asio::buffer(reply, reply_size));
				break;
			}
			else if (reply[3] != socks_atyp_ipv6 && tcp_endpoint->address().is_v6())
			{
				reply_size = socks_header_ipv6_size;
				reply[3] = socks_atyp_ipv6;
			}

			tcp_local_address = std::make_shared<asio::ip::address>(remote_socket.local_endpoint().address());

			// 5. Send Reply
			co_await client_socket.async_write_some(asio::buffer(reply, reply_size));

			// 6. Forward Traffic
			std::make_shared<tcp_session>(std::move(client_socket), std::move(remote_socket))->start();
			break;
		}
		case socks_cmd_bind:
		{
			if (tcp_local_address == nullptr)
			{
				reply_size = socks_header_ipv4_size;
				reply[0] = socks_version;
				reply[1] = socks_reply_command_not_supported;
				reply[3] = socks_atyp_ipv4;
				co_await asio::async_write(client_socket, asio::buffer(reply, reply_size));
				break;
			}

			asio::error_code ec;
			tcp_acceptor acceptor(client_socket.get_executor());
			acceptor.set_option(asio::detail::socket_option::integer<SOL_SOCKET, SO_RCVTIMEO>{ 60000 });
			uint16_t listener_port = acceptor.local_endpoint().port();
			reply[1] = socks_reply_success;
			if (tcp_local_address->is_v6())
			{
				reply_size = socks_header_ipv6_size;
				reply[3] = socks_atyp_ipv6;
				asio::ip::address_v6::bytes_type v6_bytes = tcp_local_address->to_v6().to_bytes();
				std::copy(v6_bytes.begin(), v6_bytes.end(), reply.begin() + 4);
				*(uint16_t *)(reply.data() + 20) = htons(listener_port);

			}
			else
			{
				reply_size = socks_header_ipv4_size;
				reply[3] = socks_atyp_ipv4;
				asio::ip::address_v4::bytes_type v4_bytes = tcp_local_address->to_v4().to_bytes();
				*(uint32_t *)v4_bytes.data() = *(uint32_t *)(reply.data() + 4);
				*(uint16_t *)(reply.data() + 8) = htons(listener_port);
			}

			// BIND: First Reply
			asio::async_write(client_socket, asio::buffer(reply, reply_size), [](const asio::error_code &e, size_t n) {});
			std::make_shared<tcp_binding>(std::move(client_socket), std::move(acceptor))->start(reply);
			break;
		}
		case socks_cmd_udp_associate:
		{
			asio::error_code ec;
			udp::endpoint initialise_endpoint;
			asio::ip::address local_address = client_socket.local_endpoint().address();
			if (local_address.is_v6())
			{
				reply_size = socks_header_ipv6_size;
				reply[3] = socks_atyp_ipv6;
				initialise_endpoint = udp::endpoint(udp::v6(), 0);
			}
			else
			{
				reply_size = socks_header_ipv4_size;
				reply[3] = socks_atyp_ipv4;
				initialise_endpoint = udp::endpoint(udp::v4(), 0);
			}

			if (tcp_endpoint == nullptr)
			{
				udp::resolver resolver(client_socket.get_executor());
				udp::resolver::results_type endpoints = co_await resolver.async_resolve(hostname, std::to_string(port), asio::redirect_error(asio::use_awaitable, ec));
				if (ec || endpoints.empty())
				{
					if (ec)
						reply[1] = convert_error_code(ec);
					else if (endpoints.empty())
						reply[1] = socks_reply_network_unreachable;
					co_await client_socket.async_write_some(asio::buffer(reply, reply_size));
					break;
				}
			}

			udp_socket listen_udp_socket(client_socket.get_executor(), initialise_endpoint);
			udp::endpoint binding_endpoint = listen_udp_socket.local_endpoint(ec);
			if (ec)
			{
				reply[1] = convert_error_code(ec);
				// 5. Send Reply
				co_await client_socket.async_write_some(asio::buffer(reply, reply_size));
				break;
			}

			if (local_address.is_v6())
			{
				asio::ip::address_v6::bytes_type v6_bytes = local_address.to_v6().to_bytes();
				std::copy(v6_bytes.begin(), v6_bytes.end(), reply.begin() + 4);
				*(uint16_t *)(reply.data() + 20) = htons(binding_endpoint.port());
			}
			else
			{
				asio::ip::address_v4::bytes_type v4_bytes = local_address.to_v4().to_bytes();
				*(uint32_t *)v4_bytes.data() = *(uint32_t *)(reply.data() + 4);
				*(uint16_t *)(reply.data() + 8) = htons(binding_endpoint.port());
			}

			// 5. Send Reply
			co_await client_socket.async_write_some(asio::buffer(reply, reply_size));

			// 6. Forward Traffic
			std::make_shared<udp_session>(std::move(client_socket), std::move(listen_udp_socket))->start();
			break;
		}
		default:
		{
			std::cerr << "Unsupported command: " << static_cast<int>(command) << std::endl;
			reply_size = socks_header_ipv4_size;
			reply[0] = socks_version;
			reply[1] = socks_reply_command_not_supported;
			reply[3] = socks_atyp_ipv4;
			co_await asio::async_write(client_socket, asio::buffer(reply, reply_size));
			co_return;
		}
		}
	}
	catch (std::exception &e)
	{
		std::printf("socks5_access Exception: %s\n", e.what());
	}
}

awaitable<void> listener_ipv4(const char *username, const char *password, uint16_t port = 1080)
{
	asio::any_io_executor executor = co_await this_coro::executor;
	try
	{
		tcp_acceptor acceptor(executor, { tcp::v4(), port });
		while (true)
		{
			tcp_socket socket = co_await acceptor.async_accept();
			co_spawn(executor, socks5_access(std::move(socket), username, password), detached);
		}
	}
	catch (std::exception &e)
	{
		std::printf("IPv4 socks5_listen Exception: %s\n", e.what());
	}
}

awaitable<void> listener_ipv6(const char *username, const char *password, uint16_t port = 1080)
{
	asio::any_io_executor executor = co_await this_coro::executor;
	try
	{
		tcp_acceptor acceptor(executor, { tcp::v6(), port });
		while (true)
		{
			tcp_socket socket = co_await acceptor.async_accept();
			co_spawn(executor, socks5_access(std::move(socket), username, password), detached);
		}
	}
	catch (std::exception &e)
	{
		std::printf("IPv6 socks5_listen Exception: %s\n", e.what());
		if constexpr (linux_system)
		{
			std::printf("Fallback to IPv4\n");
			co_spawn(executor, listener_ipv4(nullptr, nullptr), detached);
		}
	}
}

int main(int argc, char *argv[])
{
	try
	{
		asio::io_context io_context;

		asio::signal_set signals(io_context, SIGINT, SIGTERM);
		signals.async_wait([&](auto, auto) { io_context.stop(); });

		if (argc == 1)
		{
			co_spawn(io_context, listener_ipv6(nullptr, nullptr), detached);
			if constexpr (!linux_system)
				co_spawn(io_context, listener_ipv4(nullptr, nullptr), detached);
		}
		else if (argc == 2)
		{
			int port = std::stoi(argv[1]);
			if (port < 1 || port > 65535)
			{
				std::printf("Incorrect port number: %d\n", port);
				return 1;
			}
			co_spawn(io_context, listener_ipv6(nullptr, nullptr, (uint16_t)port), detached);
			if constexpr (!linux_system)
				co_spawn(io_context, listener_ipv4(nullptr, nullptr, (uint16_t)port), detached);
		}
		else if (argc == 3)
		{
			co_spawn(io_context, listener_ipv6(argv[1], argv[2]), detached);
			if constexpr (!linux_system)
				co_spawn(io_context, listener_ipv4(argv[1], argv[2]), detached);
		}
		else if (argc == 4)
		{
			int port = std::stoi(argv[1]);
			if (port < 1 || port > 65535)
			{
				std::printf("Incorrect port number: %d\n", (uint16_t)port);
				return 1;
			}
			co_spawn(io_context, listener_ipv6(argv[2], argv[3], port), detached);
			if constexpr (!linux_system)
				co_spawn(io_context, listener_ipv4(argv[2], argv[3], port), detached);
		}
		else
		{
			std::printf("Incorrect arguments\n");
			return 1;
		}

		io_context.run();
	}
	catch (std::exception &e)
	{
		std::printf("Exception: %s\n", e.what());
	}
	return 0;
}