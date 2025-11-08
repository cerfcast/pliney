#include "pisa/utils.h"
#include "pisa/plugin.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <dlfcn.h>

char stringify_buffer[46] = {
    0,
};

/*
 * Not safe for multiple threads.
 */
const char *stringify_ip(ip_addr_t addr) {
  memset(stringify_buffer, 0, sizeof(char) * 46);

  if (addr.family == INET_ADDR_V4) {
    struct in_addr to_convert;
    to_convert.s_addr = addr.addr.ipv4.s_addr;
    const char *stringed = inet_ntop(
        AF_INET, &to_convert, (char *)stringify_buffer, 16 * sizeof(char));
    return stringed;
  } else if (addr.family == INET_ADDR_V6) {
    struct in6_addr to_convert;
    to_convert = addr.addr.ipv6;
    const char *stringed = inet_ntop(
        AF_INET6, &to_convert, (char *)stringify_buffer, 46 * sizeof(char));
    return stringed;
  }
  error("Attempted to stringify an IP address that was neither V4 nor V6.\n");
  return "";
}

void selectively_copy_ip(ip_addr_t *dest, ip_addr_t *src) {
  if (ip_set(*src)) {
    dest->addr = src->addr;
  }
  if (src->port != 0) {
    dest->port = src->port;
  }

  dest->family = src->family;
}

int ip_set(ip_addr_t addr) {
  // Check whether the family is set -- that's our clue.
  return addr.family != 0;
}

bool ip_to_socket(ip_addr_t addr, uint8_t type, int *fd) {
  // Check whether the IP address is valid. If it is not, then return -1.
  if (!ip_set(addr)) {
    return false;
  }

  if (type != INET_DGRAM && type != INET_STREAM) {
    return false;
  }

  *fd = socket(addr.family == INET_ADDR_V4 ? AF_INET : AF_INET6,
                type == INET_STREAM ? SOCK_STREAM : SOCK_DGRAM, 0);
  return true;
}

int ip_parse(const char *to_parse, ip_addr_t *result) {
  char storage[sizeof(struct in6_addr)] = {
      0,
  };

  if (0 < inet_pton(AF_INET6, to_parse, storage)) {
    struct in6_addr *addr = (struct in6_addr *)storage;
    result->addr.ipv6 = *addr;
    result->family = INET_ADDR_V6;
    return 1;
  }
  if (0 < inet_pton(AF_INET, to_parse, storage)) {
    struct in_addr *addr = (struct in_addr *)storage;
    result->addr.ipv4 = *addr;
    result->family = INET_ADDR_V4;
    return 1;
  }
  return -1;
}

int sockaddr_to_ip(const struct sockaddr *saddr, socklen_t saddr_len,
                   ip_addr_t *addr) {

  if (saddr_len == sizeof(struct sockaddr_in6)) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)saddr;
    addr->addr.ipv6 = sin6->sin6_addr;
    addr->family = INET_ADDR_V6;
    addr->port = sin6->sin6_port;
    return 1;
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in *)saddr;
    addr->addr.ipv4 = sin->sin_addr;
    addr->family = INET_ADDR_V4;
    addr->port = sin->sin_port;
    return 1;
  }
  return -1;
}

int ip_to_sockaddr(ip_addr_t addr, struct sockaddr **result) {
  struct sockaddr_storage *saddr_raw =
      (struct sockaddr_storage *)calloc(sizeof(struct sockaddr_storage), 1);

  if (addr.family == INET_ADDR_V4) {
    struct sockaddr_in *saddr = (struct sockaddr_in *)saddr_raw;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = addr.addr.ipv4.s_addr;
    saddr->sin_port = addr.port;
    *result = (struct sockaddr *)saddr;
    return sizeof(struct sockaddr_in);
  } else if (addr.family == INET_ADDR_V6) {
    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)saddr_raw;
    saddr->sin6_addr = addr.addr.ipv6;
    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = addr.port;
    *result = (struct sockaddr *)saddr;
    return sizeof(struct sockaddr_in6);
  }
  return -1;
}

int _debug_level() {
  static int *_debug_level = NULL;

  if (_debug_level == NULL) {
    _debug_level = (int *)dlsym(RTLD_DEFAULT, "plugin_debug_level");
  }

  if (_debug_level) {
    return *_debug_level;
  }

  return 0;
}

void debug(const char *fmt, ...) {
  int dl = _debug_level();

  if (dl >= DEBUG_LEVEL) {
    printf("Debug: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
  }
}

void warn(const char *fmt, ...) {
  int dl = _debug_level();

  if (dl >= WARN_LEVEL) {
    printf("Warn: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
  }
}

void trace(const char *fmt, ...) {
  int dl = _debug_level();

  if (dl >= TRACE_LEVEL) {
    printf("Trace: ");
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
  }
}

void error(const char *fmt, ...) {
  printf("Error: ");
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("\n");
}

bool parse_to_value(const char *valuev, uint8_t *valuec, const char **names,
                    const uint8_t *values, size_t nvalues) {
  for (size_t i = 0; i < nvalues; i++) {
    if (!strcmp(valuev, names[i])) {
      *valuec = values[i];
      return true;
    }
  }
  return false;
}
