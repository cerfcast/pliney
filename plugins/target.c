#include "api/plugin.h"
#include "api/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int load() { return 1; }

char *plugin_name = "target";

char *name() { return plugin_name; }

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  ip_addr_t *addr = (ip_addr_t *)malloc(sizeof(ip_addr_t));

  if (argc > 1) {
    char *invalid = NULL;
    uint16_t port = strtol(args[1], &invalid, 10);
    if (invalid && *invalid == '\0') {
      addr->port = htons(port);
    } else {
      char *err = (char *)calloc(255, sizeof(char));
      snprintf(err, 255, "Could not convert %s to a port number", args[1]);
      configuration_result.errstr = err;
    }
  } else {
    warn("Target plugin using default port of 80.\n");
    addr->port = htons(80);
  }

  if (argc > 0 && (0 < ip_parse(args[0], addr))) {
    configuration_result.configuration_cookie = addr;
    return configuration_result;
  }

  free(addr);
  configuration_result.errstr = "Invalid IP/port combination";
  return configuration_result;
}

generate_result_t generate(ip_addr_t source, ip_addr_t target, body_p body,
                           void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    ip_addr_t *parsed_target = (ip_addr_t *)cookie;

    result.destination = *parsed_target;
    result.source = source;
    result.body = body;
    result.success = 1;

    free(cookie);

  } else {
    result.success = 0;
  }

  return result;
}