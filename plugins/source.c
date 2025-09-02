#include "api/plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int load() {
  return 1;
}

char *plugin_name = "source";

char *name() { return plugin_name; }

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  return configuration_result;
}

generate_result_t generate(ip_addr_t source, ip_addr_t target, body_p body,
                           void *cookie) {

  generate_result_t result;

  result.destination.family = INET_ADDR_V4;
  result.destination.addr.ipv4.s_addr = inet_addr("8.8.8.8");
  result.body.data = (uint8_t *)malloc(50);
  result.body.len = 50;

  return result;
}