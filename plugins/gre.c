#include "api/native.h"
#include "api/plugin.h"
#include "api/utils.h"
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

char *plugin_name = "gre";

struct __attribute__((packed)) grehdr {
  union {
    uint8_t checksum_present : 1;
    uint16_t reserved0;
    uint8_t version : 3;
  } b1;
  uint16_t protocol_type;
};

typedef struct {
  ip_addr_t addr;
  struct sockaddr_storage saddr;
  int socket;
} grep_cookie_t;

configuration_result_t generate_configuration(int argc, const char **args) {

  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};
  if (!argc) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "GRE plugin got no target.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  grep_cookie_t gcookiel;
  memset(&gcookiel, 0, sizeof(grep_cookie_t));

  // If it is not possible to parse as an IP address, try a DNS lookup.
  if (0 > ip_parse(args[0], &gcookiel.addr)) {
    struct addrinfo *resolveds = NULL;
    int dns_result = getaddrinfo(args[0], NULL, NULL, &resolveds);
    if (dns_result < 0) {
      char *err = (char *)calloc(255, sizeof(char));
      snprintf(err, 255, "Error looking up %s: %s.", args[0],
               gai_strerror(dns_result));
      configuration_result.errstr = err;
    } else {
      struct addrinfo *resolved = resolveds;
      sockaddr_to_ip(resolved->ai_addr, resolved->ai_addrlen, &gcookiel.addr);
      freeaddrinfo(resolveds);
    }
  }

  if (configuration_result.errstr) {
    configuration_result.configuration_cookie = NULL;
    return configuration_result;
  }

  struct sockaddr *native_ip = NULL;
  socklen_t native_ip_len = 0;
  native_ip_len = ip_to_sockaddr(gcookiel.addr, &native_ip);
  memcpy(&gcookiel.saddr, native_ip, native_ip_len);
  // TODO: Make that better.
  free(native_ip);

  gcookiel.socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (gcookiel.socket < 0) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not open the tunnel socket: %s", strerror(errno));
    configuration_result.errstr = err;
  }

  if (connect(gcookiel.socket, (struct sockaddr *)&gcookiel.saddr,
              native_ip_len)) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not bind to the tunnel socket: %s",
             strerror(errno));
    configuration_result.errstr = err;
  }

  // Now that we are sure things are okay, let's move the configuration cookie
  // onto the heap.
  grep_cookie_t *gcookie = (grep_cookie_t *)calloc(1, sizeof(grep_cookie_t));
  memcpy(gcookie, &gcookiel, sizeof(grep_cookie_t));
  configuration_result.configuration_cookie = gcookie;

  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {
  generate_result_t result;
  result.success = true;

  if (!cookie) {
    return result;
  }
  grep_cookie_t *gcookie = (grep_cookie_t *)cookie;

  char buf[1500] = {
      0,
  };

  struct iphdr *iph = (struct iphdr *)buf;
  struct grehdr *grh = (struct grehdr *)(buf + sizeof(struct iphdr));
  char *body = (char *)(buf + sizeof(struct iphdr) + sizeof(struct grehdr));

  size_t encapsulating_header_len =
      sizeof(struct iphdr) + sizeof(struct grehdr);

  iph->version = 0x4;
  iph->ihl = 0x5;
  iph->ttl = 64;

  if (gcookie->addr.family == PLINEY_IPVERSION4) {
    struct sockaddr_in *saddr = (struct sockaddr_in *)&gcookie->addr;
    iph->daddr = saddr->sin_addr.s_addr;
  } else {
    assert(false);
  }

  iph->protocol = 47;

  grh->protocol_type = htons(0x800);
  grh->b1.version = 0x0;

  void *native_packet_p = body;
  size_t native_packet_len = 1500 - encapsulating_header_len;

  if (!to_native_packet(packet->transport, *packet, (void **)&native_packet_p,
                        &native_packet_len)) {
    error("Could not convert to a native packet.");
    result.success = false;
    return result;
  }

  size_t total_len =
      native_packet_len + sizeof(struct grehdr) + sizeof(struct iphdr);

  int send_result = send(gcookie->socket, buf, total_len, 0);

  if (send_result < 0) {
    error("There was an error sending the encapsulated packet: %s (errno: %d).",
          strerror(errno), errno);
  }
  return result;
}

cleanup_result_t cleanup(void *cookie) {
  cleanup_result_t result = {.success = true, .errstr = NULL};

  if (cookie) {
    grep_cookie_t *gcookie = (grep_cookie_t *)cookie;
    close(gcookie->socket);
    free(cookie);
  }

  return result;
}

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "<IP or HOSTNAME>";
  result.usage = 
  "Encapsulate the packet in a GRE tunnel to the specified IP\n"
  "or HOSTNAME.";
  // clang-format on

  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  info->cleanup = cleanup;
  info->usage = usage;
  return true;
}