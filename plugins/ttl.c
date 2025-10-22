#include "api/plugin.h"
#include "api/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

char *plugin_name = "ttl";

#define DEFAULT_TTL 64

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  uint8_t *ttl = (uint8_t *)malloc(sizeof(uint8_t));

  if (argc == 0) {
    warn("TTL plugin using default TTL of %d.\n", DEFAULT_TTL);
    *ttl = DEFAULT_TTL;
    configuration_result.configuration_cookie = (void *)ttl;
    return configuration_result;
  }

  char *invalid = NULL;
  uint8_t maybe_ttl = strtol(args[0], &invalid, 10);

  if (invalid && *invalid == '\0') {
    *ttl = maybe_ttl;
    configuration_result.configuration_cookie = (void *)ttl;
    return configuration_result;
  }

  free(ttl);
  char *err = (char *)calloc(255, sizeof(char));
  snprintf(err, 255, "Could not convert %s to a TTL value", args[0]);
  configuration_result.errstr = err;

  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {
  generate_result_t result;
  result.success = true;

  if (cookie != NULL) {
    uint8_t *ttl = (uint8_t *)cookie;
    packet->header.ttl = *ttl;
  }

  return result;
}

cleanup_result_t cleanup(void *cookie) {
  if (cookie != NULL) {
    free(cookie);
  }

  cleanup_result_t result = {.success = true, .errstr = NULL};
  return result;
}

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "<TTL>";
  result.usage = 
  "Set the time to live on the packet to TTL.";
  // clang-format on

  return result;
}


bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  info->cleanup = cleanup;
  info->usage = usage;
  return true;
}