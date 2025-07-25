cmake_minimum_required(VERSION 3.21)

project(packetline DESCRIPTION "Make packets.")

set(MAIN_SRCS src/packetline.cpp)

add_executable(packetline ${MAIN_SRCS})
target_include_directories(packetline PRIVATE include)
set_property(TARGET packetline PROPERTY CXX_STANDARD 20)

add_library(target SHARED "src/target.c")
target_include_directories(target PRIVATE include)

add_dependencies(packetline target)
