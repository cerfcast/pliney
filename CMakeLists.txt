cmake_minimum_required(VERSION 3.21)

project(pliney DESCRIPTION "Make packets.")

set(PLINEY_MAIN src/packetline.cpp)
set(PLINEY_INTERSTITIAL src/interstitial.cpp)
set(PLINEY_SRCS src/apis/utils.c src/logger.cpp src/pipeline.cpp src/plugin.cpp src/apis/exthdrs.c src/cli.cpp src/executors.cpp src/utilities.cpp src/usage.cpp)
set(PLUGIN_LIB_SRCS src/apis/utils.c src/apis/exthdrs.c src/apis/native.c)

add_executable(pliney ${PLINEY_MAIN} ${PLINEY_SRCS})
target_include_directories(pliney PRIVATE include)
set_property(TARGET pliney PROPERTY CXX_STANDARD 23)
set_property(TARGET pliney PROPERTY C_STANDARD 23)
target_link_options(pliney PRIVATE "-Wl,--export-dynamic")

add_library(plineyi SHARED ${PLINEY_INTERSTITIAL} ${PLINEY_SRCS})
target_include_directories(plineyi PRIVATE include)
set_property(TARGET plineyi PROPERTY CXX_STANDARD 23)
set_property(TARGET plineyi PROPERTY C_STANDARD 23)

add_library(target SHARED "plugins/target.c" ${PLUGIN_LIB_SRCS})
target_include_directories(target PRIVATE include)
set_property(TARGET target PROPERTY C_STANDARD 23)
set_property(TARGET target PROPERTY OUTPUT_NAME pliney_pl_target)

add_library(source SHARED "plugins/source.c" ${PLUGIN_LIB_SRCS})
target_include_directories(source PRIVATE include)
set_property(TARGET source PROPERTY C_STANDARD 23)
set_property(TARGET source PROPERTY OUTPUT_NAME pliney_pl_source)

add_library(body SHARED "plugins/body.c" ${PLUGIN_LIB_SRCS})
target_include_directories(body PRIVATE include)
set_property(TARGET body PROPERTY C_STANDARD 23)
set_property(TARGET body PROPERTY OUTPUT_NAME pliney_pl_body)

add_library(exthdr-padn SHARED "plugins/exthdr-padn.c" ${PLUGIN_LIB_SRCS})
target_include_directories(exthdr-padn PRIVATE include)
set_property(TARGET exthdr-padn PROPERTY C_STANDARD 23)
set_property(TARGET exthdr-padn PROPERTY OUTPUT_NAME pliney_pl_exthdr_padn)

add_library(ttl SHARED "plugins/ttl.c" ${PLUGIN_LIB_SRCS})
target_include_directories(ttl PRIVATE include)
set_property(TARGET ttl PROPERTY C_STANDARD 23)
set_property(TARGET ttl PROPERTY OUTPUT_NAME pliney_pl_ttl)

add_library(diffserv SHARED "plugins/diffserv.c" ${PLUGIN_LIB_SRCS})
target_include_directories(diffserv PRIVATE include)
set_property(TARGET diffserv PROPERTY C_STANDARD 23)
set_property(TARGET diffserv PROPERTY OUTPUT_NAME pliney_pl_diffserv)

add_library(cong SHARED "plugins/cong.c" ${PLUGIN_LIB_SRCS})
target_include_directories(cong PRIVATE include)
set_property(TARGET cong PROPERTY C_STANDARD 23)
set_property(TARGET cong PROPERTY OUTPUT_NAME pliney_pl_cong)

add_library(error SHARED "plugins/error.c" ${PLUGIN_LIB_SRCS})
target_include_directories(error PRIVATE include)
set_property(TARGET error PROPERTY C_STANDARD 23)
set_property(TARGET error PROPERTY OUTPUT_NAME pliney_pl_error)

add_library(raw SHARED "plugins/raw.c" ${PLUGIN_LIB_SRCS})
target_include_directories(raw PRIVATE include)
set_property(TARGET raw PROPERTY C_STANDARD 23)
set_property(TARGET raw PROPERTY OUTPUT_NAME pliney_pl_raw)

add_library(gre SHARED "plugins/gre.c" ${PLUGIN_LIB_SRCS})
target_include_directories(gre PRIVATE include)
set_property(TARGET gre PROPERTY C_STANDARD 23)
set_property(TARGET gre PROPERTY OUTPUT_NAME pliney_pl_gre)


add_dependencies(pliney target)
add_dependencies(pliney target)
add_dependencies(pliney source)
add_dependencies(pliney body)
add_dependencies(pliney exthdr-padn)
add_dependencies(pliney ttl)
add_dependencies(pliney diffserv)
add_dependencies(pliney cong)
add_dependencies(pliney error)
add_dependencies(pliney raw)
add_dependencies(pliney gre)

# Try to find libpcap to determine whether to enable log plugin support.
find_package(PkgConfig)
pkg_check_modules(PCAP libpcap)
if(${PCAP_FOUND})
    add_library(log SHARED "plugins/log.c" ${PLUGIN_LIB_SRCS})
    target_include_directories(log PRIVATE include)
    set_property(TARGET log PROPERTY C_STANDARD 23)
    set_property(TARGET log PROPERTY OUTPUT_NAME pliney_pl_log)
    target_link_libraries(log ${PCAP_LIBRARIES})
    target_include_directories(log PRIVATE ${PCAP_INCLUDE_DIRS})
    add_dependencies(pliney log)
else()
    message(WARNING "Could not find libpcap -- disabling log plugin support")
endif()


add_subdirectory(test)

set(FORMATTABLE_FILES "${PLINEY_SRCS}")
list(APPEND FORMATTABLE_FILES "${PLINEY_MAIN}")
list(APPEND FORMATTABLE_FILES "${PLINEY_INTERSTITIAL}")
list(APPEND FORMATTABLE_FILES "${PLUGIN_LIB_SRCS}")
list(APPEND FORMATTABLE_FILES plugins/target.c plugins/source.c plugins/body.c plugins/exthdr-padn.c plugins/ttl.c plugins/diffserv.c plugins/cong.c plugins/log.c plugins/error.c plugins/raw.c plugins/gre.c)
list(TRANSFORM FORMATTABLE_FILES PREPEND "${CMAKE_SOURCE_DIR}/" OUTPUT_VARIABLE FORMATTABLE_FILES)
list(JOIN FORMATTABLE_FILES "\n" FORMATTABLE_FILES)

file(GENERATE OUTPUT ${CMAKE_SOURCE_DIR}/cicd/clang-format-configure CONTENT "${FORMATTABLE_FILES}")
add_custom_target(clang-format COMMAND ${CMAKE_SOURCE_DIR}/cicd/format.sh "format" "${CMAKE_SOURCE_DIR}/cicd/clang-format-configure")
add_custom_target(clang-format-check COMMAND ${CMAKE_SOURCE_DIR}/cicd/format.sh "check" "${CMAKE_SOURCE_DIR}/cicd/clang-format-configure")
