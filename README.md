# cpp20-socks5demo
Socks5 Server Demo implemented in C++20 coroutine with ASIO library

[简体中文版](#简体中文版)
[繁體中文版](#繁體中文版)

## Supported Features
- IPv4 Connection
- IPv6 Connection
- ‘No Auth’ method
- TCP `Connect` request
- UDP `Associate` request

## Features Not supported
- GSSAPI
- Username / Password Authentication method
- TCP `BIND` request

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
- TCP `Connect` 请求
- UDP `Associate` 请求

## 未实现的特性
- GSSAPI
- 用户名 / 密码 认证模式
- TCP `BIND` 请求

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
- TCP `Connect` 請求
- UDP `Associate` 請求

## 未實現的特性
- GSSAPI
- 用戶名稱 / 密碼 認證模式
- TCP `BIND` 請求

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