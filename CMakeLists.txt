cmake_minimum_required(VERSION 3.21)

project(packetline DESCRIPTION "Make packets.")

set(MAIN_SRCS src/packetline.cpp src/apis/utils.c src/logger.cpp src/pipeline.cpp src/plugin.cpp src/apis/exthdrs.c src/cli.cpp)
set(PLUGIN_LIB_SRCS src/apis/utils.c src/apis/exthdrs.c)
add_executable(packetline ${MAIN_SRCS})
target_include_directories(packetline PRIVATE include)
set_property(TARGET packetline PROPERTY CXX_STANDARD 23)
set_property(TARGET packetline PROPERTY C_STANDARD 23)
target_link_options(packetline PRIVATE "-Wl,--export-dynamic-symbol" "plugin_debug_level")

add_library(target SHARED "plugins/target.c" ${PLUGIN_LIB_SRCS})
target_include_directories(target PRIVATE include)
set_property(TARGET target PROPERTY C_STANDARD 23)

add_library(source SHARED "plugins/source.c" ${PLUGIN_LIB_SRCS})
target_include_directories(source PRIVATE include)
set_property(TARGET source PROPERTY C_STANDARD 23)

add_library(type SHARED "plugins/type.c" ${PLUGIN_LIB_SRCS})
target_include_directories(type PRIVATE include)
set_property(TARGET type PROPERTY C_STANDARD 23)

add_library(body SHARED "plugins/body.c" ${PLUGIN_LIB_SRCS})
target_include_directories(body PRIVATE include)
set_property(TARGET body PROPERTY C_STANDARD 23)

add_library(exthdr-padn SHARED "plugins/exthdr-padn.c" ${PLUGIN_LIB_SRCS})
target_include_directories(exthdr-padn PRIVATE include)
set_property(TARGET exthdr-padn PROPERTY C_STANDARD 23)

add_dependencies(packetline target)
add_dependencies(packetline source)
add_dependencies(packetline type)
add_dependencies(packetline body)
add_dependencies(packetline exthdr-padn)

set(FORMATTABLE_FILES "${MAIN_SRCS}")
list(APPEND FORMATTABLE_FILES "${PLUGIN_LIB_SRCS}")
list(APPEND FORMATTABLE_FILES plugins/target.c plugins/source.c plugins/body.c plugins/exthdr-padn.c)
list(TRANSFORM FORMATTABLE_FILES PREPEND "${CMAKE_SOURCE_DIR}/" OUTPUT_VARIABLE FORMATTABLE_FILES)
list(JOIN FORMATTABLE_FILES "\n" FORMATTABLE_FILES)

file(GENERATE OUTPUT ${CMAKE_SOURCE_DIR}/cicd/clang-format-configure CONTENT "${FORMATTABLE_FILES}")
add_custom_target(clang-format COMMAND ${CMAKE_SOURCE_DIR}/cicd/format.sh "format" "${CMAKE_SOURCE_DIR}/cicd/clang-format-configure")
add_custom_target(clang-format-check COMMAND ${CMAKE_SOURCE_DIR}/cicd/format.sh "check" "${CMAKE_SOURCE_DIR}/cicd/clang-format-configure")
