#ifndef _TYPES_H
#define _TYPES_H

#include <netinet/in.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  size_t len;
  uint8_t *data;
} data_p;

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

#define INET_STREAM 6
#define INET_DGRAM 17

typedef struct {
  uint8_t family;
  union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
  } addr;
  uint16_t port;
} ip_addr_t;

typedef struct {
  data_p all;
  data_p ip;
  data_p ip_options;
  data_p transport;
  data_p body;
} packet_t;

#ifdef __cplusplus
}
#endif


#endif
