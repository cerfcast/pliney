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

typedef struct {
  uint8_t type;
  uint8_t len;
  uint8_t *data;
} extension_p;

typedef struct {
  size_t extensions_count;
  extension_p **extensions_values;
} extensions_p;

typedef struct {
  uint8_t diffserv;
  uint8_t cong;
  uint8_t ttl;
} header_p;

#define INET_ADDR_V4 4
#define INET_ADDR_V6 6

#define INET_STREAM 1
#define INET_DGRAM 2

typedef struct {
  uint8_t family;
  union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
  } addr;
  uint16_t port;
} ip_addr_t;

typedef struct {
  ip_addr_t source;
  ip_addr_t target;
  header_p header;
  extensions_p header_extensions;
  body_p body;
} packet_t;

typedef struct {
  uint8_t connection_type;
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

typedef generate_result_t (*generate_t)(packet_t *packet, void*);
typedef configuration_result_t (*generate_configuration_t)(int argc, const char **);
typedef cleanup_result_t (*cleanup_t)(void *);

typedef struct {
  char *name;
  generate_t generator;
  generate_configuration_t configurator;
  cleanup_t cleanup;
} plugin_t;

typedef bool (*load_t)(plugin_t *);

bool load(plugin_t *info);

const char *stringify_ip(ip_addr_t addr);

#ifdef __cplusplus
}
#endif
#endif