cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(socks5demo LANGUAGES C CXX)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(${CMAKE_SYSTEM_NAME} MATCHES "^DragonFly?" OR ${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	include_directories("/usr/local/include")
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
	include_directories("/usr/pkg/include")
endif()

find_package(Threads REQUIRED)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
	add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
endif()

add_executable(${PROJECT_NAME} src/main.cpp)

add_subdirectory(src)
set_property(TARGET socks5demo PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
