#ifndef _PLUGIN_H
#define _PLUGIN_H

#include <netinet/in.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  size_t len;
  uint8_t *data;
} body_p;

#define INET_ADDR_V4 4
#define INET_ADDR_V6 6

typedef struct {
  uint8_t family;
  uint8_t stream;
  union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
  } addr;
  uint16_t port;
} ip_addr_t;

typedef struct {
  ip_addr_t destination;
  ip_addr_t source;
  body_p body;
} generate_result_t;

char *name();
int load();
generate_result_t generate(ip_addr_t source, ip_addr_t target, body_p body, void*);
void *generate_configuration(const char **args);

typedef char *(*name_t)();
typedef int (*load_t)();
typedef generate_result_t (*generate_t)(ip_addr_t, ip_addr_t, body_p, void*);
typedef void* (*generate_configuration_t)(const char **);

const char *stringify_ip(ip_addr_t addr);

#ifdef __cplusplus
}
#endif
#endif