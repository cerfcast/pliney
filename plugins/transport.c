#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

char *plugin_name = "transport";

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (!argc) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Transport plugin got no transport.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  uint8_t transport = 0;

  if (!strcmp(args[0], "tcp")) {
    transport = PLINEY_TCP;
  } else if (!strcmp(args[0], "udp")) {
    transport = PLINEY_UDP;
  } else {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Transport value invalid: %s.", args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }

  uint8_t *transport_p = (uint8_t *)calloc(1, sizeof(uint8_t));
  *transport_p = transport;

  configuration_result.configuration_cookie = transport_p;
  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    // TODO: Fix
    pisa_value_t meta_value;
    meta_value.tpe = BYTE;
    meta_value.value.byte = *(uint8_t *)cookie;
    pisa_program_add_meta_inst(program, "TRANSPORT", meta_value);
    result.success = 1;
  } else {
    result.success = 0;
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
  result.params = "<udp,tcp>";
  result.usage = "TODO";
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