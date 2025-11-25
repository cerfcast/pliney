all: build/pliney.xdp.o build/pliney.tc.o

build/pliney.xdp.o: build/pliney.xdp.c
	clang -target bpf -O2 -c -g -o build/pliney.xdp.o -Ixdp build/pliney.xdp.c

build/pliney.tc.o: build/pliney.tc.c
	clang -target bpf -O2 -c -g -o build/pliney.tc.o -Ixdp build/pliney.tc.c

load:
	sudo ip link set dev eno1 xdpgeneric obj build/pliney.xdp.o sec xdp

unload:
	sudo ip link set dev eno1 xdpgeneric off

load-tc:
	sudo tc filter add dev eno1 egress prio 10 bpf da obj build/pliney.tc.o sec egress

unload-tc:
	sudo tc filter del dev eno1 egress prio 10 bpf da obj build/pliney.tc.o sec egress

load-clsact-tc:
	sudo tc qdisc add dev eno1 clsact

