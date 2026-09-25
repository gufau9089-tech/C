cmake_minimum_required(VERSION 3.15)
project(sqlite3 C)

add_library(sqlite3 STATIC sqlite3.c)

target_include_directories(sqlite3 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
