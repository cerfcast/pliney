#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/priority.h"
#include "pisa/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

char *plugin_name = "cong";

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  uint8_t maybe_parsed_ecn = 0;

  if (argc == 0) {
    warn("No congestion value specified to the cong plugin.");
    return configuration_result;
  }

  if (!parse_to_value(args[0], &maybe_parsed_ecn, ECN_NAMES, ECN_VALUES,
                      sizeof(ECN_VALUES))) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not convert %s to a value ECN value", args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }
  uint8_t *parsed_ecn = (uint8_t *)malloc(sizeof(uint8_t));
  *parsed_ecn = maybe_parsed_ecn;

  configuration_result.configuration_cookie = parsed_ecn;
  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {

    uint8_t target_family = 0;

    if (!pisa_program_find_target_family(program, &target_family)) {
      result.success = 0;
      return result;
    }

    pisa_inst_t set_ecn_inst;
    set_ecn_inst.op = SET_FIELD;
    set_ecn_inst.fk.field =
        target_family == PLINEY_IPVERSION4 ? IPV4_ECN : IPV6_ECN;
    set_ecn_inst.value.tpe = BYTE;
    set_ecn_inst.value.value.byte = *(uint8_t *)cookie;
    result.success = pisa_program_add_inst(program, &set_ecn_inst);

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
  result.params = "<ect1, ect0, ce, not-ect>";
  result.usage = 
  "Set the congestion value of the DSCP field to the specified\n"
  "value.";
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
