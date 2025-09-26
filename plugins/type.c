#include "api/plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

char *plugin_name = "type";

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL, .errstr = NULL};
  uint32_t *stream_or_dgram = (uint32_t*)malloc(sizeof(uint32_t));

  *stream_or_dgram = 0;
  if (!strcmp("stream", args[0])) {
    *stream_or_dgram = INET_STREAM;
  } else if (!strcmp("dgram", args[0])) {
    *stream_or_dgram = INET_DGRAM;
  } else {
    configuration_result.errstr = "Invalid type given";
    return configuration_result;
  }

  configuration_result.configuration_cookie = stream_or_dgram;

  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {

  generate_result_t result;

  uint32_t stream_or_dgram = *(uint32_t*)cookie;

  if (stream_or_dgram != 0) {
    result.connection_type = stream_or_dgram;
    result.success = 1;
  } else {
    result.success = 0;
  }

  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  return true;
}


