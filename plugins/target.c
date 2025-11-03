#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/types.h"
#include "pisa/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

char *plugin_name = "target";

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (!argc) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Target plugin got no target.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  ip_addr_t *addr = (ip_addr_t *)calloc(sizeof(ip_addr_t), 1);

  // If it is not possible to parse as an IP address, try a DNS lookup.
  if (0 > ip_parse(args[0], addr)) {
    struct addrinfo *resolveds = NULL;
    int dns_result = getaddrinfo(args[0], NULL, NULL, &resolveds);
    if (dns_result < 0) {
      char *err = (char *)calloc(255, sizeof(char));
      snprintf(err, 255, "Error looking up %s: %s", args[0],
               gai_strerror(dns_result));
      configuration_result.errstr = err;
    } else {
      struct addrinfo *resolved = resolveds;
      sockaddr_to_ip(resolved->ai_addr, resolved->ai_addrlen, addr);
      freeaddrinfo(resolveds);
    }
  }

  if (!configuration_result.errstr && argc > 1) {
    char *invalid = NULL;
    uint16_t port = strtol(args[1], &invalid, 10);
    if (invalid && *invalid == '\0') {
      addr->port = htons(port);
    } else {
      char *err = (char *)calloc(255, sizeof(char));
      snprintf(err, 255, "Could not convert %s to a port number", args[1]);
      configuration_result.errstr = err;
    }
  } else {
    warn("Target plugin was not given a port.\n");
  }

  if (configuration_result.errstr) {
    configuration_result.configuration_cookie = NULL;
    free(addr);
    return configuration_result;
  }

  configuration_result.configuration_cookie = addr;
  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    ip_addr_t *parsed_target = (ip_addr_t *)cookie;

    pisa_inst_t set_target_inst;
    set_target_inst.op = SET_FIELD;
    set_target_inst.fk.field =
        parsed_target->family == INET_ADDR_V4 ? IPV4_TARGET : IPV6_TARGET;
    set_target_inst.value.value.ipaddr = *parsed_target;
    result.success = pisa_program_add_inst(program, &set_target_inst);

    if (!result.success) {
      return result;
    }

    pisa_inst_t set_target_port_inst;
    set_target_port_inst.op = SET_FIELD;
    set_target_port_inst.fk.field = parsed_target->family == INET_ADDR_V4
                                        ? IPV4_TARGET_PORT
                                        : IPV6_TARGET_PORT;
    set_target_port_inst.value.value.ipaddr = *parsed_target;
    result.success = pisa_program_add_inst(program, &set_target_port_inst);

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
  result.params = "<IP or HOSTNAME> [PORT]";
  result.usage = 
  "Set the target address of the packet to IP or the address\n"
  "resolved from a DNS lookup of HOSTNAME. The packet's\n"
  "existing target port will only be overwritten if PORT\n"
  "is specified.";
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