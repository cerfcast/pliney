#include "api/utils.h"
#include "api/plugin.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <dlfcn.h>

bool has_ip(ip_addr_t addr) {}

const char *stringify_ip(ip_addr_t addr) {
  if (addr.family == INET_ADDR_V4) {
    struct in_addr to_convert;
    const char *buff = (const char *)malloc(sizeof(char) * 128);

    to_convert.s_addr = addr.addr.ipv4.s_addr;
    const char *stringed = inet_ntop(AF_INET, &to_convert, (char *)buff, 128);
    return stringed;

  } else if (addr.family == INET_ADDR_V6) {
  }
  return "";
}

int ip_valid(ip_addr_t addr) {
  return (addr.stream == INET_STREAM || addr.stream == INET_DGRAM);
}

int ip_to_socket(ip_addr_t addr) {
  // Check whether the IP address is valid. If it is not, then return -1.
  if (!ip_valid(addr)) {
    return -1;
  }

  return socket(addr.family == INET_ADDR_V4 ? AF_INET : AF_INET6,
                addr.stream == INET_STREAM ? SOCK_STREAM : SOCK_DGRAM, 0);
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
    saddr->sin6_family = AF_INET6;
    assert(false); // TODO
    *result = (struct sockaddr *)saddr;
    return sizeof(struct sockaddr_in6);
  }
  assert(false); // Handle errors.
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
    va_list args;
    va_start(args, fmt);
    printf("Debug: ");
    printf(fmt, args);
  }
}

void warn(const char *fmt, ...) {
  int dl = _debug_level();

  if (dl >= WARN_LEVEL) {
    va_list args;
    va_start(args, fmt);
    printf("Warn: ");
    printf(fmt, args);
  }
}

void trace(const char *fmt, ...) {
  int dl = _debug_level();

  if (dl >= TRACE_LEVEL) {
    va_list args;
    va_start(args, fmt);
    printf("Trace: ");
    printf(fmt, args);
  }
}
