#include "lib/types.h"
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

char *plugin_name = "icmp-extension";

#define ENVIRONMENT 4
#define ENVIRONMENT_POWER 1

#define PROBE 3
#define PROBE_BY_NAME 1

typedef struct __attribute__((packed)) {
  uint8_t version;
  uint8_t reserved;
  uint16_t checksum;
} ext_header_t;

typedef struct __attribute__((packed)) {
  uint16_t length;
  uint8_t class;
  uint8_t ctype;
  // Payload.
} ext_object_header_t;

typedef struct {
  ext_header_t ext_header;
  data_p object;
} icmp_ext_cookie_t;

const char *ICMP_EXT_NAMES[] = {"probe", "environment"};
const uint8_t ICMP_EXT_VALUES[] = {PROBE, ENVIRONMENT};

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  uint8_t maybe_parsed_icmp_ext_type = 0;
  uint8_t maybe_parsed_icmp_ext_class = 0;
  uint8_t maybe_parsed_icmp_ext_ctype = 0;

  if (argc == 0) {
    warn("No ICMP extension type specified to the icmp extension plugin.");
    return configuration_result;
  }

  if (!parse_to_value(args[0], &maybe_parsed_icmp_ext_type, ICMP_EXT_NAMES,
                      ICMP_EXT_VALUES, sizeof(ICMP_EXT_VALUES))) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not convert %s to a valid ICMP extension type",
             args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }

  if (maybe_parsed_icmp_ext_type == ENVIRONMENT) {
    uint32_t maybe_power_present = 0;
    uint32_t maybe_power_idle = 0;

    if (argc > 1) {
      char *invalid = NULL;
      maybe_power_present = htonl(strtol(args[1], &invalid, 10));
      if (invalid && *invalid != '\0') {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(err, 255,
                 "Could not convert %s to a valid present power value",
                 args[1]);
        configuration_result.errstr = err;
      }
    }

    if (argc > 2) {
      char *invalid = NULL;
      maybe_power_idle = htonl(strtol(args[2], &invalid, 10));
      if (invalid && *invalid != '\0') {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(err, 255, "Could not convert %s to a valid idle power value",
                 args[2]);
        configuration_result.errstr = err;
      }
    }

    icmp_ext_cookie_t *cookie =
        (icmp_ext_cookie_t *)calloc(1, sizeof(icmp_ext_cookie_t));
    cookie->ext_header.version = 2 << 4;
    cookie->ext_header.checksum = 0;

    size_t power_len = sizeof(ext_object_header_t) + 8;
    uint8_t *power = (uint8_t *)calloc(power_len, sizeof(uint8_t));

    ext_object_header_t *obj_header = (ext_object_header_t *)power;

    obj_header->class = ENVIRONMENT;
    obj_header->ctype = ENVIRONMENT_POWER;
    obj_header->length = htons(power_len);

    uint32_t *present_power = (uint32_t *)(power + sizeof(ext_object_header_t));
    *present_power = maybe_power_present;
    uint32_t *idle_power =
        (uint32_t *)(power + sizeof(ext_object_header_t) + sizeof(uint32_t));
    *idle_power = maybe_power_idle;

    cookie->object.data = power;
    cookie->object.len = power_len;

    configuration_result.configuration_cookie = cookie;
    return configuration_result;
  } else if (maybe_parsed_icmp_ext_type == PROBE) {

    if (argc < 2) {
      char *err = (char *)calloc(255, sizeof(char));
      snprintf(err, 255, "Missing interface name to probe.");
      configuration_result.errstr = err;
      return configuration_result;
    }

    const char *interface_name = args[1];
    size_t interface_name_len = strlen(interface_name);
    // When we are probing by name, the space for the name needs to be 32-bit
    // aligned.
    size_t interface_name_len_padded =
        (interface_name_len + (0x4 - 1)) & (~(0x4 - 1));

    icmp_ext_cookie_t *cookie =
        (icmp_ext_cookie_t *)calloc(1, sizeof(icmp_ext_cookie_t));
    cookie->ext_header.version = 2 << 4;
    cookie->ext_header.checksum = 0;

    size_t ext_object_header_and_object_len =
        sizeof(ext_object_header_t) + interface_name_len_padded;
    uint8_t *ext_object_header_and_object =
        (uint8_t *)calloc(ext_object_header_and_object_len, sizeof(uint8_t));

    ext_object_header_t *object_header =
        (ext_object_header_t *)ext_object_header_and_object;

    object_header->class = PROBE;
    // Assume (for now) that we probe by name.
    object_header->ctype = PROBE_BY_NAME;
    object_header->length = htons(ext_object_header_and_object_len);

    // When probing by name, the extension object is just the name of the
    // interface.
    char *ext_object =
        (char *)ext_object_header_and_object + sizeof(ext_object_header_t);
    memcpy(ext_object, interface_name, interface_name_len);

    cookie->object.data = ext_object_header_and_object;
    cookie->object.len = ext_object_header_and_object_len;
    configuration_result.configuration_cookie = cookie;
    return configuration_result;
  }

  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    icmp_ext_cookie_t *icmp_cookie = (icmp_ext_cookie_t *)cookie;

    pisa_inst_t set_icmp_ext_header;
    memset(&set_icmp_ext_header, 0, sizeof(pisa_inst_t));
    set_icmp_ext_header.op = SET_TRANSPORT_EXTENSION;
    set_icmp_ext_header.value.tpe = PTR;
    set_icmp_ext_header.value.value.ptr.data =
        (uint8_t *)&icmp_cookie->ext_header;
    set_icmp_ext_header.value.value.ptr.len = sizeof(ext_header_t);
    result.success = pisa_program_add_inst(program, &set_icmp_ext_header);

    if (!result.success) {
      return result;
    }

    pisa_inst_t set_icmp_object_inst;
    memset(&set_icmp_object_inst, 0, sizeof(pisa_inst_t));
    set_icmp_object_inst.op = SET_FIELD;
    set_icmp_object_inst.fk.field = APPLICATION_BODY;
    set_icmp_object_inst.value.tpe = PTR;
    set_icmp_object_inst.value.value.ptr.data = icmp_cookie->object.data;
    set_icmp_object_inst.value.value.ptr.len = icmp_cookie->object.len;
    result.success = pisa_program_add_inst(program, &set_icmp_object_inst);

  } else {
    result.success = 0;
  }

  return result;
}

cleanup_result_t cleanup(void *cookie) {
  if (cookie != NULL) {
    icmp_ext_cookie_t *icmp_cookie = (icmp_ext_cookie_t *)cookie;

    if (icmp_cookie->object.len != 0) {
      free(icmp_cookie->object.data);
    }

    free(cookie);
  }

  cleanup_result_t result = {.success = true, .errstr = NULL};
  return result;
}

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "<probe, environment> [TYPE_SPECIFIC_OPTIONS]";
  result.usage = 
  "Create the ICMP extension object with the given type to\n"
  "be placed in an ICMP packet. Depending on the type,\n"
  "TYPE_SPECIFIC_OPTIONS will be:\n"
  "probe: INTERFACE_NAME\n"
  "       The interface name for which to probe.\n"
  "environment: [PRESENT] [IDLE]\n"
  "             The present and idle power of the host.";
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
