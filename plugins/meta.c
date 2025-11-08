#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

char *plugin_name = "meta";

typedef struct {
  char *key;
  size_t key_len;
  char *value;
  size_t value_len;
} metap_cookie_t;

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc < 2) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Meta plugin needs key and value as argument.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  metap_cookie_t *meta_cookie =
      (metap_cookie_t *)calloc(1, sizeof(metap_cookie_t));

  size_t key_len = strlen(args[0]) + 1;
  size_t value_len = strlen(args[1]) + 1;

  char *key = (char *)calloc(key_len, sizeof(char));
  char *value = (char *)calloc(value_len, sizeof(char));

  strcpy(key, args[0]);
  strcpy(value, args[1]);

  meta_cookie->value = value;
  meta_cookie->value_len = value_len;
  meta_cookie->key = key;
  meta_cookie->key_len = key_len;

  configuration_result.configuration_cookie = (void *)meta_cookie;
  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    // TODO: Fix
    metap_cookie_t *meta_cookie = (metap_cookie_t *)cookie;

    pisa_value_t meta_value;
    meta_value.tpe = PTR;
    meta_value.value.ptr.data = (uint8_t *)meta_cookie->value;
    meta_value.value.ptr.len = meta_cookie->value_len;
    pisa_program_add_meta_inst(program, meta_cookie->key, meta_value);

    debug("Generated with key %s", meta_cookie->key);
    result.success = 1;
  } else {
    result.success = 0;
  }

  return result;
}

cleanup_result_t cleanup(void *cookie) {
  if (cookie != NULL) {
    metap_cookie_t *meta_cookie = (metap_cookie_t *)cookie;
    free(meta_cookie->key);
    free(meta_cookie->value);
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