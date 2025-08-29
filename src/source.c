#include "api/plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int load() {
  printf("Loaded source plugin!\n");
  return 1;
}

char *plugin_name = "source";

char *name() { return plugin_name; }

void *generate_configuration(const char **args) {
  return NULL;
}

generate_result_t generate(ip_addr_t source, ip_addr_t target, body_p body,
                           void *cookie) {

  printf("I was given a source ip address: -%s-\n", stringify_ip(source));
  printf("I was given a target ip address: -%s-\n", stringify_ip(target));

  generate_result_t result;

  result.destination.family = INET_ADDR_V4;
  result.destination.addr.ipv4.s_addr = inet_addr("8.8.8.8");
  result.body.data = (uint8_t *)malloc(50);
  result.body.len = 50;

  return result;
}