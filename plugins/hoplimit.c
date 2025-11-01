#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

char *plugin_name = "hoplimit";

#define DEFAULT_TTL 64

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  uint8_t *ttl = (uint8_t *)malloc(sizeof(uint8_t));

  if (argc == 0) {
    warn("Hoplimit plugin using default limit of %d.\n", DEFAULT_TTL);
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
  snprintf(err, 255, "Could not convert %s to a hoplimit value", args[0]);
  configuration_result.errstr = err;

  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;
  result.success = true;

  if (cookie != NULL) {
    uint8_t *ttl = (uint8_t *)cookie;

    pisa_inst_t set_ttl_inst;

    set_ttl_inst.op = SET_FIELD;
    set_ttl_inst.prot = IPV6;
    set_ttl_inst.fk.field = IPV6_HL;
    set_ttl_inst.value.value.byte = *ttl;
    set_ttl_inst.value.tpe = BYTE;

    result.success = pisa_program_add_inst(program, &set_ttl_inst);
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
  result.params = "<HL>";
  result.usage = 
  "Set the hoplimit on the packet to HL.";
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