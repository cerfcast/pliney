
cmake_minimum_required(VERSION 3.12)
project(lua-sockets-cmake VERSION 1.0.0 DESCRIPTION "Lua build for a project subdirectory" LANGUAGES C)

option(BUILD_SHARED_LIBS "Build as shared library" ON)

set(srcDir luasocket/src)

set(srcFiles luasocket.c timeout.c buffer.c io.c auxiliar.c compat.c options.c inet.c except.c select.c tcp.c udp.c usocket.c)

set(publicHeaderFiles luasocket.h compat.h)

list(TRANSFORM srcFiles PREPEND ${srcDir}/)
list(TRANSFORM publicHeaderFiles PREPEND ${srcDir}/)

add_library(lua-socket
    ${srcFiles})

target_compile_definitions(lua-socket
    PRIVATE
    $<$<PLATFORM_ID:Linux>:LUA_USE_LINUX LUA_COMPAT_5_2>)

target_compile_options(lua-socket
    PRIVATE
    $<$<OR:$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>>:
    -Wextra -Wshadow -Wsign-compare -Wundef -Wwrite-strings -Wredundant-decls
    -Wdisabled-optimization -Waggregate-return -Wdouble-promotion -Wdeclaration-after-statement
    -Wmissing-prototypes -Wnested-externs -Wstrict-prototypes -Wc++-compat -Wold-style-definition>)

set(includeDir ${CMAKE_CURRENT_BINARY_DIR}/include/)
file(COPY ${publicHeaderFiles} DESTINATION ${includeDir}/luasocket/)

add_library(lua-socket-header
    INTERFACE)

target_include_directories(lua-socket-header
    INTERFACE
    ${includeDir})

target_link_libraries(lua-socket
    INTERFACE
    lua-socket-header)

add_library(lua::socket-lib ALIAS lua-socket)
add_library(lua::socket-header ALIAS lua-socket-header)



