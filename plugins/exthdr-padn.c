#include "api/exthdrs.h"
#include "api/plugin.h"
#include "api/utils.h"
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
    configuration_result.errstr =
        "Must provide at least a type and length to the hbh-padn plugin.";
    return configuration_result;
  }

  uint8_t type = 0;
  if (!strcmp(args[0], "hbh")) {
    type = IPV6_HOPOPTS;
  } else if (!strcmp(args[0], "dst")) {
    type = IPV6_DSTOPTS;
  } else {
    configuration_result.errstr = "Invalid type provided.";
    return configuration_result;
  }

  extension_p *new_extension = (extension_p *)calloc(1, sizeof(extension_p));

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
  new_extension->type = type;

  configuration_result.configuration_cookie = new_extension;

  return configuration_result;
};

generate_result_t generate(ip_addr_t source, ip_addr_t target,
                           extensions_p extensions, body_p body, void *cookie) {

  generate_result_t result;
  result.destination = target;
  result.source = source;
  result.body = body;
  result.extensions = extensions;

  if (target.family != INET_ADDR_V6) {
    error("Can only set extension headers for IPv6 targets.");
    result.success = 0;
  }

  size_t new_extension_idx = 0;
  if (!add_extension(&result.extensions, &new_extension_idx)) {
    result.success = 0;
  }

  result.success = 1;

  extension_p *extensions_from_cookie = (extension_p *)(cookie);
  result.extensions.extensions_values[new_extension_idx] =
      extensions_from_cookie;

  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  return true;
}
