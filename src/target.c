#include <stdio.h>
#include <stdlib.h>
#include "plugin.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int load() {
    printf("Loaded target plugin!\n");
    return 1;
}

char *plugin_name = "target";

char *name() {
    return plugin_name;
}

generate_result_t generate(ip_addr_t addr, body_p body) {

    generate_result_t result;

    result.address.type = INET_ADDR_V4;
    result.address.addr.ipv4.s_addr = inet_addr("8.8.8.8");
    result.body.data = (uint8_t*)malloc(50);
    result.body.len = 50;

    return result;
}