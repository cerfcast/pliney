#include "api/plugin.h"
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

void *generate_configuration(const char **args) {
  uint32_t *target_addr = (uint32_t*)malloc(sizeof(uint32_t));
  *target_addr = inet_addr(args[0]);

  return target_addr;
}

generate_result_t generate(ip_addr_t source, ip_addr_t target, body_p body, void *cookie) {

  printf("I was given a source ip address: -%s-\n", stringify_ip(source));
  printf("I was given a target ip address: -%s-\n", stringify_ip(target));

  generate_result_t result;

  result.destination.family = INET_ADDR_V4;
  result.destination.addr.ipv4.s_addr = *(uint32_t*)cookie;
  result.destination.stream = 0;
  result.destination.port = 53;
  result.body.data = (uint8_t *)malloc(50);
  result.body.len = 50;

  return result;
}