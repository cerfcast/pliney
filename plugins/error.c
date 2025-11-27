#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

char *plugin_name = "error";

#define DEFAULT_ERROR_BYTE 0x67

typedef struct {
  double error_rate;
  uint8_t error_byte;
} errorp_cookie_t;

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc == 0) {
    warn("No error rate set for error plugin.");
    return configuration_result;
  }

  char *endptr = NULL;

  uint8_t error_byte = DEFAULT_ERROR_BYTE;

  if (argc > 1) {
    long maybe_error_byte = strtol(args[1], &endptr, 16);
    if (endptr && *endptr != '\0') {
      configuration_result.errstr = (char *)calloc(255, sizeof(char));
      sprintf(configuration_result.errstr,
              "Could not convert given error byte (%s) to a number.", args[1]);
      return configuration_result;
    }

    if (maybe_error_byte > 0xff) {
      configuration_result.errstr = (char *)calloc(255, sizeof(char));
      sprintf(configuration_result.errstr,
              "Given error byte (%s) will not fit in a byte.", args[1]);
      return configuration_result;
    }

    error_byte = maybe_error_byte;
  }

  double error_rate = strtod(args[0], &endptr);

  if (endptr && *endptr != '\0') {
    configuration_result.errstr = (char *)calloc(255, sizeof(char));
    sprintf(configuration_result.errstr,
            "Could not convert given error rate (%s) to a number.", args[0]);
    return configuration_result;
  }

  if (error_rate > 1) {
    configuration_result.errstr = (char *)calloc(255, sizeof(char));
    sprintf(configuration_result.errstr,
            "An error rate of more than 1 is meaningless.");
    return configuration_result;
  }

  errorp_cookie_t *configuration_c = calloc(1, sizeof(errorp_cookie_t));
  configuration_c->error_rate = error_rate;
  configuration_c->error_byte = error_byte;
  configuration_result.configuration_cookie = (void *)configuration_c;

  return configuration_result;
}

void error_packet_cb(packet_t packet, void *cookie) {
  if (cookie != NULL) {
    errorp_cookie_t *configuration_c = (errorp_cookie_t *)cookie;

    struct timeval t;
    if (gettimeofday(&t, NULL) < 0) {
      error("There was an error getting the time of day to seed the random "
            "number generator in the error plugin.");
    }

    debug(
        "Used %d as the seed for random number generation in the error plugin.",
        t.tv_usec);
    srandom(t.tv_usec);

    size_t flip_count = 0;
    for (size_t i = 0; i < packet.body.len; i++) {
      double r = random();
      double rr = r / (((unsigned long long)2 << 30) - 1);

      trace("calculated error rate in the error plugin: %f", rr);

      if (rr > (1 - configuration_c->error_rate)) {
        flip_count++;
        packet.body.data[i] = configuration_c->error_byte;
      }
    }

    debug("error plugin flipped %d out of %d bytes.", flip_count,
          packet.body.len);
  }
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    data_p *body = (data_p *)cookie;

    pisa_inst_t set_exec_after_packet_built_cb_inst;
    set_exec_after_packet_built_cb_inst.op = EXEC_AFTER_PACKET_BUILT;
    set_exec_after_packet_built_cb_inst.value.tpe = CALLBACK;
    set_exec_after_packet_built_cb_inst.value.value.callback.callback = (void *)error_packet_cb;
    set_exec_after_packet_built_cb_inst.value.value.callback.cookie = cookie;
    result.success = pisa_program_add_inst(program, &set_exec_after_packet_built_cb_inst);

    result.success = 1;

  } else {
    result.success = 0;
  }

  return result;
}


cleanup_result_t cleanup(void *cookie) {
  cleanup_result_t result = {.success = true, .errstr = NULL};

  if (cookie) {
    free(cookie);
  }
  return result;
}

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "<ERROR_RATE> [BYTE]";
  result.usage = 
  "With ERROR_RATE probability, change each byte in the packet\n"
  "body to BYTE. If BYTE is not specified, 0x67 is used. Only\n"
  "applies to the Cli and Packet runners.";
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