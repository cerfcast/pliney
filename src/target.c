#include "plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int load() {
  printf("Loaded target plugin!\n");
  return 1;
}

char *plugin_name = "target";

char *name() { return plugin_name; }

generate_result_t generate(ip_addr_t source, ip_addr_t target, body_p body) {

  printf("I was given a source ip address: -%s-\n", stringify_ip(source));
  printf("I was given a target ip address: -%s-\n", stringify_ip(target));

  generate_result_t result;

  result.destination.type = INET_ADDR_V4;
  result.destination.addr.ipv4.s_addr = inet_addr("8.8.8.8");
  result.destination.port = 53;
  result.body.data = (uint8_t *)malloc(50);
  result.body.len = 50;

  return result;
}