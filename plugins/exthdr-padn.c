#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

char *plugin_name = "exthdr-padn";

#define DEFAULT_BYTE_VALUE 0xff

struct __attribute__((packed)) extension_header_tlv {
  uint8_t type;
  uint8_t len;
  uint8_t value[];
};

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc < 2) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Extension Header plugin got no arguments.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  uint8_t type = 0;
  if (!strcmp(args[0], "hbh")) {
    type = IPV6_HOPOPTS;
  } else if (!strcmp(args[0], "dst")) {
    type = IPV6_DSTOPTS;
  } else {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Invalid type provided.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  pisa_ip_opt_ext_t *new_extension =
      (pisa_ip_opt_ext_t *)calloc(1, sizeof(pisa_ip_opt_ext_t));

  size_t hbh_size = strtol(args[1], NULL, 10);
  size_t total_hbh_size = 2 + hbh_size;

  uint8_t *new_extension_data =
      (uint8_t *)calloc(total_hbh_size, sizeof(uint8_t));
  memset(new_extension_data, DEFAULT_BYTE_VALUE, total_hbh_size);
  struct extension_header_tlv *tlv =
      (struct extension_header_tlv *)(new_extension_data);

  tlv->type = 0x1;
  tlv->len = hbh_size;

  if (argc > 2) {
    uint8_t byte = strtol(args[2], NULL, 16);
    memset(tlv->value, byte, hbh_size);
  }

  new_extension->data = new_extension_data;
  new_extension->len = total_hbh_size;
  new_extension->oe.ext_type = type;

  configuration_result.configuration_cookie = new_extension;

  return configuration_result;
};

generate_result_t generate(pisa_program_t *program, void *cookie) {

  generate_result_t result;

  if (cookie) {
    pisa_ip_opt_ext_t *extension = (pisa_ip_opt_ext_t *)cookie;

    pisa_inst_t add_ip_extension_inst;
    add_ip_extension_inst.op = ADD_IP_OPT_EXT;
    add_ip_extension_inst.value.tpe = IP_EXT;
    add_ip_extension_inst.value.value.ext = *extension;

    pisa_program_add_inst(program, &add_ip_extension_inst);

    result.success = 1;
  }
  return result;
}

cleanup_result_t cleanup(void *cookie) {
  if (cookie != NULL) {
    pisa_ip_opt_ext_t *extension = (pisa_ip_opt_ext_t *)cookie;
    free(extension->data);
    free(cookie);
  }

  cleanup_result_t result = {.success = true, .errstr = NULL};
  return result;
}

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "<dst, hbh> <SIZE> [BYTE]";
  result.usage = 
  "Add a PadN option to the destination or hop-by-hop\n"
  "dst, hbh, respectively) IPv6 extension header with the\n"
  "specified SIZE. Optionally specify the value of the\n"
  "BYTEs in the padding. User is responsible for\n"
  "guaranteeing that the sizes of all extension headers\n"
  "meet alignment and other requirements.";
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
