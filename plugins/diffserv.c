#include "api/plugin.h"
#include "api/priority.h"
#include "api/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

char *plugin_name = "diffserv";

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  uint8_t maybe_parsed_codepoint = 0;

  if (argc == 0) {
    warn("No codepoint specified to the DSCP plugin.");
    return configuration_result;
  }

  if (!parse_to_value(args[0], &maybe_parsed_codepoint, DSCP_CODEPOINT_NAMES, DSCP_CODEPOINT_VALUES, sizeof(DSCP_CODEPOINT_VALUES))) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not convert %s to a DSCP codepoint", args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }
  uint8_t *parsed_codepoint = (uint8_t*)malloc(sizeof(uint8_t));
  *parsed_codepoint = maybe_parsed_codepoint;

  configuration_result.configuration_cookie = parsed_codepoint;
  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {
  generate_result_t result;
  result.success = false;

  if (cookie != 0) {
    uint8_t *codepoint = (uint8_t*)cookie;
    packet->header.diffserv = *codepoint;
  }

  result.success = true;
  return result;
}

cleanup_result_t cleanup(void *cookie) {
  if (cookie != NULL) {
    free(cookie);
  }

  cleanup_result_t result = {.success = true, .errstr = NULL};
  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  info->cleanup = cleanup;
  return true;
}