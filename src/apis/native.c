#include "api/native.h"
#include "api/plugin.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>

bool to_native_dscp(uint8_t x, uint8_t *y) {
  *y = x << 2;
  return true;
}

bool to_native_ecn(uint8_t x, uint8_t *y) {
  *y = x;
  return true;
}

bool to_native_tos(uint8_t diffserv, uint8_t cong, uint8_t *native) {
  uint8_t native_dscp = 0;
  uint8_t native_ecn = 0;

  if (!to_native_dscp(diffserv, &native_dscp)) {
    return false;
  }
  if (!to_native_ecn(cong, &native_ecn)) {
    return false;
  }
  *native = native_dscp | native_ecn;
  return true;
}

bool to_native_packet_v6(uint8_t type, packet_t packet, void **native,
                         size_t *native_len) {

  size_t transport_size = 0;

  if (type == INET_DGRAM) {
    transport_size = sizeof(struct udphdr);
  } else if (type == INET_STREAM) {
    transport_size = sizeof(struct tcphdr);
  } else {
    return false;
  }

  size_t calculated_native_len =
      packet.body.len + sizeof(struct ip6_hdr) + transport_size;
  char *data = NULL;
  bool user_provided_buffer = false;

  // User may have given us a place to put the packet ...
  if (*native != NULL) {
    // They did ... make sure that it was big enough.
    if (*native_len < calculated_native_len) {
      return false;
    }
    data = *native;
    user_provided_buffer = true;
    *native_len = calculated_native_len;
  } else {
    // They did not ... we will make our own.
    *native_len = calculated_native_len;
    data = (char *)calloc(*native_len, sizeof(char));
    *native = data;
  }

  struct ip6_hdr *native_ip = (struct ip6_hdr *)(data + 0);

  char *native_body = (char *)(data + sizeof(struct ip6_hdr) + transport_size);

  native_ip->ip6_src = packet.source.addr.ipv6;
  native_ip->ip6_dst = packet.target.addr.ipv6;

  native_ip->ip6_flow = htonl(0x60000000);
  native_ip->ip6_plen = htons(packet.body.len + transport_size);

  // Cannot write directly into the header because of its odd offset.
  uint8_t tclass = 0;
  if (!to_native_tos(packet.header.diffserv, packet.header.cong, &tclass)) {
    if (!user_provided_buffer) {
      free(data);
    }
    return false;
  }
  native_ip->ip6_flow |= htonl(tclass << 20);

  native_ip->ip6_hlim = packet.header.ttl;

  if (type == INET_DGRAM) {
    struct udphdr *native_udp =
        (struct udphdr *)(data + sizeof(struct ip6_hdr));
    native_udp->check = 0;
    native_udp->dest = packet.target.port;
    native_udp->source = packet.source.port;
    native_udp->len = htons(packet.body.len + sizeof(struct udphdr));
    native_ip->ip6_nxt = IPPROTO_UDP;
  } else if (type == INET_STREAM) {
    struct tcphdr *native_tcp =
        (struct tcphdr *)(data + sizeof(struct ip6_hdr));
    native_tcp->check = 0;
    native_tcp->dest = packet.target.port;
    native_tcp->source = packet.source.port;
    native_tcp->doff = 5;
    native_ip->ip6_nxt = IPPROTO_TCP;
  }

  memcpy(native_body, packet.body.data, packet.body.len);
  return true;
}
bool to_native_packet_v4(uint8_t type, packet_t packet, void **native,
                         size_t *native_len) {

  size_t transport_size = 0;

  if (type == INET_DGRAM) {
    transport_size = sizeof(struct udphdr);
  } else if (type == INET_STREAM) {
    transport_size = sizeof(struct tcphdr);
  } else {
    return false;
  }

  size_t calculated_native_len =
      packet.body.len + sizeof(struct iphdr) + transport_size;
  char *data = NULL;
  bool user_provided_buffer = false;
  // User may have given us a place to put the packet ...
  if (*native != NULL) {
    // They did ... make sure that it was big enough.
    if (*native_len < calculated_native_len) {
      return false;
    }
    data = *native;
    user_provided_buffer = true;
    *native_len = calculated_native_len;
  } else {
    // They did not ... we will make our own.
    *native_len = calculated_native_len;
    data = (char *)calloc(*native_len, sizeof(char));
    *native = data;
  }

  struct iphdr *native_ip = (struct iphdr *)(data + 0);

  char *native_body = (char *)(data + sizeof(struct iphdr) + transport_size);

  native_ip->check = 0;

  native_ip->saddr = packet.source.addr.ipv4.s_addr;
  native_ip->daddr = packet.target.addr.ipv4.s_addr;

  native_ip->version = 4;
  native_ip->ihl = 5;
  native_ip->id = 0;
  native_ip->frag_off = 0;

  native_ip->tot_len = htons(packet.body.len + transport_size + 20);

  if (!to_native_tos(packet.header.diffserv, packet.header.cong,
                     &native_ip->tos)) {
    if (!user_provided_buffer) {
      free(data);
    }
    return false;
  }

  native_ip->ttl = packet.header.ttl;

  if (type == INET_DGRAM) {
    struct udphdr *native_udp = (struct udphdr *)(data + sizeof(struct iphdr));
    native_udp->check = 0;
    native_udp->dest = packet.target.port;
    native_udp->source = packet.source.port;
    native_udp->len = htons(packet.body.len + sizeof(struct udphdr));
    native_ip->protocol = IPPROTO_UDP;
  } else if (type == INET_STREAM) {
    struct tcphdr *native_tcp = (struct tcphdr *)(data + sizeof(struct iphdr));
    native_tcp->check = 0;
    native_tcp->dest = packet.target.port;
    native_tcp->source = packet.source.port;
    native_tcp->doff = 5;
    native_ip->protocol = IPPROTO_TCP;
  }

  memcpy(native_body, packet.body.data, packet.body.len);
  return true;
}

bool to_native_packet(uint8_t type, packet_t packet, void **native,
                      size_t *native_len) {

  if (packet.target.family == INET_ADDR_V6) {
    return to_native_packet_v6(type, packet, native, native_len);
  }
  return to_native_packet_v4(type, packet, native, native_len);
}
