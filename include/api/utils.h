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
int ip_to_socket(ip_addr_t addr);
int ip_parse(const char *to_parse, ip_addr_t *result);
int debug_level();

#ifdef __cplusplus
}
#endif
#endif