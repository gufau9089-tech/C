cmake_minimum_required(VERSION 3.15)
project(stb C)

add_library(stb INTERFACE)

target_include_directories(stb INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
