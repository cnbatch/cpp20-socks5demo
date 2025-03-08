# cpp20-socks5demo
Socks5 Server Demo implemented in C++20 coroutine with ASIO library

[简体中文版](#简体中文版)

[繁體中文版](#繁體中文版)

## Supported Features
- IPv4 Connection
- IPv6 Connection
- ‘No Auth’ method
- Username / Password Authentication method
- TCP `Connect` request
- TCP `BIND` request
- UDP `Associate` request

## Features Not supported
- GSSAPI

### Username / Password Authentication
Run socks5demo with username and password.

For example, username is ‘user’, password is ‘door’:

```
./socks5demo user door
```

### Specify Port Number
Default port number is 1080. If the port number must be changed, for example, use 1180 instead:
```
./socks5demo 1180
```

### Specify Port Number + Username / Password Authentication

```
./socks5demo 1180 user door
```

## Requirements
- `ASIO` library must be installed first.
- Compiler that supports C++20

## How to build
### Option 1: CMake
```
git clone https://github.com/cnbatch/cpp20-socks5demo.git
cd cpp20-socks5demo
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

### Option 2 (Windows Only): sln
1. `git clone https://github.com/cnbatch/cpp20-socks5demo.git`
2. Open `sln\socks5demo.sln`
3. Build the project.

# 简体中文版
## 支持的特性
- IPv4 连接
- IPv6 连接
- ‘No Auth’ 认证模式
- 用户名 / 密码 认证模式
- TCP `Connect` 请求
- TCP `BIND` 请求
- UDP `Associate` 请求

## 未实现的特性
- GSSAPI

### 用户名 / 密码 认证模式
运行 socks5demo 并传入用户名与密码。

例如，用户名是‘user’，密码是‘door’：

```
./socks5demo user door
```

### 指定端口号
默认端口号是 1080，如果需要使用其他端口号，可以自行指定，例如使用 1180 端口号
```
./socks5demo 1180
```

### 指定端口号 + 用户名 / 密码 认证模式

```
./socks5demo 1180 user door
```

## 编译前置要求
- 必须先安装 `ASIO` 库
- 支持C++20的编译器

## 如何编译
### 选项 1: CMake
```
git clone https://github.com/cnbatch/cpp20-socks5demo.git
cd cpp20-socks5demo
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

### 选项 2 (仅限 Windows): sln
1. `git clone https://github.com/cnbatch/cpp20-socks5demo.git`
2. 打开 `sln\socks5demo.sln`
3. 编译项目


# 繁體中文版

## 已實現的特性
- IPv4 連接
- IPv6 連接
- ‘No Auth’ 認證方式
- 用戶名稱 / 密碼 認證模式
- TCP `Connect` 請求
- TCP `BIND` 請求
- UDP `Associate` 請求

## 未實現的特性
- GSSAPI

### 用戶名稱 / 密碼 認證模式
執行 socks5demo 並傳入用戶名稱及密碼。

例如，用戶名稱是‘user’，密碼是‘door’：

```
./socks5demo user door
```

### 指定通訊埠號
預設通訊埠號是 1080，如果需要使用其他通訊埠號，可以自行指定，例如使用 1180 通訊埠號
```
./socks5demo 1180
```

### 指定通訊埠號 + 用戶名稱 / 密碼 認證模式

```
./socks5demo 1180 user door
```

## 編譯前置要求
- 必須事先裝好 C++庫 `ASIO`
- 支援C++20的編譯器

## 如何編譯
### 選項 1: CMake
```
git clone https://github.com/cnbatch/cpp20-socks5demo.git
cd cpp20-socks5demo
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

### 選項 2 (僅限 Windows): sln
1. `git clone https://github.com/cnbatch/cpp20-socks5demo.git`
2. 打開 `sln\socks5demo.sln`
3. 編譯項目