#ifndef __PISA_UTILS_H
#define __PISA_UTILS_H

#include "pisa.h"
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERROR_LEVEL 0
#define WARN_LEVEL 1
#define DEBUG_LEVEL 2
#define TRACE_LEVEL 3

int ip_to_sockaddr(ip_addr_t addr, struct sockaddr **result);
int sockaddr_to_ip(const struct sockaddr *saddr, socklen_t saddr_len,
                   ip_addr_t *addr);
bool ip_to_socket(ip_addr_t addr, uint8_t type, int *fd);
int ip_parse(const char *to_parse, ip_addr_t *result);
int ip_set(ip_addr_t addr);
void selectively_copy_ip(ip_addr_t *dest, ip_addr_t *src);

/** parse_to_value
 * Convert a string to a value by searching parallel array of ids and names.
 *
 * The parallel arrays should be structured as
 * names:
 * name_index => name
 * values:
 * values_index => value
 *
 * where values[name_index] is the result. It is assumed that names and
 * values have the same length.
 */
bool parse_to_value(const char *valuev, uint8_t *valuec, const char **names,
                    const uint8_t *values, size_t nvalues);


void trace(const char *fmt, ...);
void debug(const char *fmt, ...);
void warn(const char *fmt, ...);
void error(const char *fmt, ...);

#define WITH_OFFSET(x, y) ((uint8_t *)x + y)

#ifdef __cplusplus
}
#endif
#endif