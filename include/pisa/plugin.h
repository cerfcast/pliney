#ifndef _PLUGIN_H
#define _PLUGIN_H

#include <netinet/in.h>
#include <stdint.h>
#include "pisa.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t success;
} generate_result_t;

typedef struct {
  void *configuration_cookie;
  char *errstr;
} configuration_result_t;

typedef struct {
  bool success;
  char *errstr;
} cleanup_result_t;

typedef struct {
  char *params;
  char *usage;
} usage_result_t;

typedef generate_result_t (*generate_t)(pisa_program_t *program, void*);
typedef void (*observe_t)(pisa_program_t *program, packet_t *, void*);
typedef configuration_result_t (*generate_configuration_t)(int argc, const char **);
typedef cleanup_result_t (*cleanup_t)(void *);
typedef usage_result_t (*usage_t)();

typedef struct {
  char *name;
  generate_t generator;
  generate_configuration_t configurator;
  observe_t observer;
  cleanup_t cleanup;
  usage_t usage;
} plugin_t;

typedef bool (*load_t)(plugin_t *);

bool load(plugin_t *info);

const char *stringify_ip(ip_addr_t addr);

#ifdef __cplusplus
}
#endif
#endif