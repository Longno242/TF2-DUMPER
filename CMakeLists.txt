cmake_minimum_required(VERSION 3.16)
project(tf2_dumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(tf2_dumper
    src/main.cpp
    src/memory_io.cpp
    src/netvar_dump.cpp
    src/pe_util.cpp
    src/process.cpp
    src/pattern.cpp
)

target_include_directories(tf2_dumper PRIVATE src)

target_link_libraries(tf2_dumper PRIVATE Psapi)

if(WIN32)
    target_compile_definitions(tf2_dumper PRIVATE NOMINMAX)
endif()

if(MSVC)
    target_compile_options(tf2_dumper PRIVATE /W4 /permissive-)
else()
    target_compile_options(tf2_dumper PRIVATE -Wall -Wextra -Wpedantic)
endif()
