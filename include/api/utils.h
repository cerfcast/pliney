#ifndef _UTILS_H
#define _UTILS_H

#include "api/plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ERROR_LEVEL 0
#define WARN_LEVEL 1
#define DEBUG_LEVEL 2
#define TRACE_LEVEL 3

int ip_to_sockaddr(ip_addr_t addr, struct sockaddr **result);
int ip_to_socket(ip_addr_t addr, uint8_t type);
int ip_parse(const char *to_parse, ip_addr_t *result);
int ip_set(ip_addr_t addr);
void copy_ip(ip_addr_t *dest, ip_addr_t *src);

void debug(const char *fmt, ...);
void warn(const char *fmt, ...);
void error(const char *fmt, ...);

#define USE_GIVEN_IN_RESULT(result)                                            \
  {                                                                            \
    result.destination = target;                                               \
    result.source = source;                                                    \
    result.body = body;                                                        \
    result.extensions = extensions;                                            \
    result.connection_type = type;                                             \
  }

#ifdef __cplusplus
}
#endif
#endif