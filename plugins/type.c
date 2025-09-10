#include "api/plugin.h"
#include "api/utils.h"
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

generate_result_t generate(ip_addr_t source, ip_addr_t target, uint8_t type, extensions_p extensions, body_p body, void *cookie) {

  generate_result_t result;

  USE_GIVEN_IN_RESULT(result);

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


