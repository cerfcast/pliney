#include "api/plugin.h"
#include "api/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

char *plugin_name = "source";

char *name() { return plugin_name; }

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc == 0) {
    warn("Source plugin used without specifying either address or port -- "
         "Making no changes.\n");
    return configuration_result;
  }

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
      return configuration_result;
    }
  } else {
    warn("Source plugin using OS-selected ephemeral port.\n");
    addr->port = 0;
  }

  if (argc > 0 && (0 < ip_parse(args[0], addr))) {
    configuration_result.configuration_cookie = addr;
    return configuration_result;
  }

  free(addr);
  configuration_result.errstr = "Invalid IP/port combination";
  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {

  generate_result_t result;

  if (cookie) {
    ip_addr_t *addr = (ip_addr_t *)cookie;
    selectively_copy_ip(&packet->source, addr);
  }

  result.success = true;
  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  return true;
}
