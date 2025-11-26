#include "pisa/plugin.h"
#include "pisa/utils.h"
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

void observe(pisa_program_t *program, packet_t *packet, void *cookie) {

  if (!cookie) {
    return;
  }

  // We will need to find the transport!

  grep_cookie_t *gcookie = (grep_cookie_t *)cookie;

#define GRE_HEADER_LEN (sizeof(struct iphdr) + sizeof(struct grehdr))
  // TODO: Determine whether a variable MTU makes sense here.
  char buf[1500] = {0};

  struct iphdr *iph = (struct iphdr *)buf;
  struct grehdr *grh = (struct grehdr *)(buf + sizeof(struct iphdr));
  iph->version = 0x4;
  iph->ihl = 0x5;
  iph->ttl = 64;

  if (gcookie->addr.family == PLINEY_IPVERSION4) {
    struct sockaddr_in *saddr = (struct sockaddr_in *)&gcookie->addr;
    iph->daddr = saddr->sin_addr.s_addr;
  } else {
    assert(false);
  }

  iph->protocol = IPPROTO_GRE;

  grh->protocol_type = htons(0x800);
  grh->b1.version = 0x0;

  void *encapsulated_packet = buf;
  size_t length_of_packet_to_encapsulate = packet->all.len;
  if (length_of_packet_to_encapsulate + GRE_HEADER_LEN > 1500) {
    size_t overflow = length_of_packet_to_encapsulate;
    length_of_packet_to_encapsulate = 1500 - GRE_HEADER_LEN;
    warn("Slicing packet from %d to %d when mirroring into GRE tunnel.");
  }
  memcpy(encapsulated_packet + GRE_HEADER_LEN, packet->all.data,
         length_of_packet_to_encapsulate);
  size_t encapsulated_packet_len =
      GRE_HEADER_LEN + length_of_packet_to_encapsulate;

  int send_result = send(gcookie->socket, buf, encapsulated_packet_len, 0);

  if (send_result < 0) {
    error("There was an error sending the encapsulated packet: %s (errno: %d).",
          strerror(errno), errno);
  }
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result = {.success = true};
  if (cookie) {
    grep_cookie_t *gcookie = (grep_cookie_t *)cookie;

    pisa_value_t pisa_transport_value = {.tpe = BYTE};
    if (!pisa_program_find_meta_value(program, "TRANSPORT",
                                      &pisa_transport_value)) {
      result.success = false;
    }
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
  info->observer = observe;
  info->cleanup = cleanup;
  info->usage = usage;
  return true;
}