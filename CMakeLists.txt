cmake_minimum_required(VERSION 3.10)
project(swiftcap C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS_RELEASE "-O3")

add_executable(swiftcap main.c)
