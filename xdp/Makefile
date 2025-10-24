build/pliney_xdp.o: build/pliney_xdp.c
	clang -target bpf -O2 -c -g -o build/pliney_xdp.o build/pliney_xdp.c

load:
	sudo ip link set dev eno1 xdpgeneric obj build/pliney_xdp.o sec xdp

unload:
	sudo ip link set dev eno1 xdpgeneric off
