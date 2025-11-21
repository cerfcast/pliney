cmake_minimum_required(VERSION 3.20)
# Add special target for compiling the generated xdp file.
project(xdp_gen DESCRIPTION "A project for testing the generated XDP code.")

add_library(xdp_gen OBJECT xdp.c)
target_compile_options(xdp_gen PRIVATE -target bpf -O2 -c -g)
set_property(TARGET xdp_gen PROPERTY OUTPUT_NAME ${CMAKE_BINARY_DIR}/xdp_gen.o)
add_custom_target(load-xdp sudo ip link set dev eno1 xdpgeneric obj $<TARGET_OBJECTS:xdp_gen> sec xdp)
add_custom_target(unload-xdp sudo ip link set dev eno1 xdpgeneric off)
add_custom_target(load-xdp-tailscale sudo ip link set dev tailscale0 xdpgeneric obj $<TARGET_OBJECTS:xdp_gen> sec xdp)
add_custom_target(unload-xdp-tailscale sudo ip link set dev tailscale0 xdpgeneric off)
