#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/utils.h"
#include <endian.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

char *plugin_name = "icmp";

typedef struct {
  uint8_t code;
  uint8_t type;
  uint32_t rest;
} icmp_extension_cookie_t;

const char *ICMP_EXT_NAMES[] = {"echo", "extended-echo"};
const uint8_t ICMP_EXT_VALUES[] = {ICMP_ECHO, ICMP_EXT_ECHO};

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  uint8_t maybe_parsed_icmp_type = 0;
  uint8_t maybe_parsed_icmp_code = 0;
  uint32_t maybe_parsed_icmp_rest = 0;

  if (argc == 0) {
    warn("No ICMP type specified to the icmp plugin.");
    return configuration_result;
  }

  if (!parse_to_value(args[0], &maybe_parsed_icmp_type, ICMP_EXT_NAMES,
                      ICMP_EXT_VALUES, sizeof(ICMP_EXT_VALUES))) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not convert %s to a value ICMP type", args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }

  if (maybe_parsed_icmp_type == ICMP_ECHO ||
      maybe_parsed_icmp_type == ICMP_EXT_ECHO) {
    uint32_t maybe_parsed_echo_id = 0;
    uint32_t maybe_parsed_echo_seq = 0;
    if (argc > 1) {
      char *invalid = NULL;
      maybe_parsed_echo_id = strtol(args[1], &invalid, 16);
      if (invalid && *invalid != '\0') {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(err, 255, "Could not convert %s to a value ICMP echo id",
                 args[1]);
        configuration_result.errstr = err;
        return configuration_result;
      }
    }

    if (argc > 2) {
      char *invalid = NULL;
      maybe_parsed_echo_seq = strtol(args[2], &invalid, 16);
      if (invalid && *invalid != '\0') {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(err, 255, "Could not convert %s to a value ICMP echo sequence",
                 args[2]);
        configuration_result.errstr = err;
        return configuration_result;
      }

      // TODO: Warn about the sequence being too big?
      if (maybe_parsed_icmp_type == ICMP_EXT_ECHO) {
        maybe_parsed_echo_seq <<= 8;
      }
    }
    maybe_parsed_icmp_rest =
        htonl((maybe_parsed_echo_id << 16) | maybe_parsed_echo_seq);
  }

  icmp_extension_cookie_t *cookie =
      (icmp_extension_cookie_t *)calloc(1, sizeof(icmp_extension_cookie_t));

  cookie->type = maybe_parsed_icmp_type;
  cookie->rest = maybe_parsed_icmp_rest;

  configuration_result.configuration_cookie = cookie;
  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    icmp_extension_cookie_t *icmp_cookie = (icmp_extension_cookie_t *)cookie;

    uint8_t pisa_program_family = PLINEY_IPVERSION4;
    if (!pisa_program_find_target_family(program, &pisa_program_family)) {
      warn("ICMP plugin cannot determine the program's IP version.");
    }

    // If the family is version 6, we will need to change the code.
    if (icmp_cookie->type == ICMP_EXT_ECHO &&
        pisa_program_family == PLINEY_IPVERSION6) {
      debug("Updated ICMP echo request type to type specific for IPv6.");
      icmp_cookie->type = ICMPV6_EXT_ECHO_REQUEST;
    }

    pisa_inst_t set_icmp_type_inst;
    memset(&set_icmp_type_inst, 0, sizeof(pisa_inst_t));
    set_icmp_type_inst.op = SET_FIELD;
    set_icmp_type_inst.fk.field = ICMP_TYPE;
    set_icmp_type_inst.value.tpe = BYTE;
    set_icmp_type_inst.value.value.byte = icmp_cookie->type;
    result.success = pisa_program_add_inst(program, &set_icmp_type_inst);

    if (!result.success) {
      return result;
    }

    pisa_inst_t set_icmp_depends_inst;
    memset(&set_icmp_depends_inst, 0, sizeof(pisa_inst_t));
    set_icmp_depends_inst.op = SET_FIELD;
    set_icmp_depends_inst.fk.field = ICMP_DEPENDS;
    set_icmp_depends_inst.value.tpe = FOUR_BYTES;
    set_icmp_depends_inst.value.value.four_bytes = icmp_cookie->rest;
    result.success = pisa_program_add_inst(program, &set_icmp_depends_inst);

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
  result.params = "<echo> [TYPE_SPECIFIC_OPTIONS]";
  result.usage = 
  "Create an ICMP packet with the given type. Depending on\n"
  "the type, TYPE_SPECIFIC_OPTIONS will be different:\n"
  "echo: [ID] [SEQUENCE]\n"
  "      The id and sequence in the request packet.\n"
  "extended-echo: [ID] [SEQUENCE]\n"
  "               The id and sequence in the request packet.";
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
