#include "plugin.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>

bool has_ip(ip_addr_t addr) {}

const char *stringify_ip(ip_addr_t addr) {
  if (addr.type == INET_ADDR_V4) {
    struct in_addr to_convert;
    const char *buff = (const char *)malloc(sizeof(char) * 128);

    to_convert.s_addr = addr.addr.ipv4.s_addr;
    const char *stringed = inet_ntop(AF_INET, &to_convert, (char *)buff, 128);
    return stringed;

  } else if (addr.type == INET_ADDR_V6) {
  }
  return "";
}

int ip_to_socket(ip_addr_t addr) {
  // Assume that all packets are part of a stream at this point.
  return socket(addr.type == INET_ADDR_V4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
}

int ip_to_sockaddr(ip_addr_t addr, struct sockaddr **result) {
  struct sockaddr_storage *saddr_raw =
      (struct sockaddr_storage *)calloc(sizeof(struct sockaddr_storage), 1);

  if (addr.type == INET_ADDR_V4) {
    struct sockaddr_in *saddr = (struct sockaddr_in *)saddr_raw;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = addr.addr.ipv4.s_addr;
    saddr->sin_port = addr.port;
    *result = (struct sockaddr *)saddr;
    return sizeof(struct sockaddr_in);
  } else if (addr.type == INET_ADDR_V6) {
    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)saddr_raw;
    saddr->sin6_family = AF_INET6;
    assert(false); // TODO
    *result = (struct sockaddr *)saddr;
    return sizeof(struct sockaddr_in6);
  }
  assert(false); // Handle errors.
}