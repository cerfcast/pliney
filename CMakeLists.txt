cmake_minimum_required(VERSION 3.21)

project(packetline DESCRIPTION "Make packets.")

set(MAIN_SRCS src/packetline.cpp src/utils.c)

add_executable(packetline ${MAIN_SRCS})
target_include_directories(packetline PRIVATE include)
set_property(TARGET packetline PROPERTY CXX_STANDARD 20)
set_property(TARGET packetline PROPERTY C_STANDARD 23)

add_library(target SHARED "src/target.c" "src/utils.c")
target_include_directories(target PRIVATE include)
set_property(TARGET target PROPERTY C_STANDARD 23)

add_library(source SHARED "src/source.c" "src/utils.c")
target_include_directories(source PRIVATE include)
set_property(TARGET source PROPERTY C_STANDARD 23)

add_dependencies(packetline target)
add_dependencies(packetline source)
