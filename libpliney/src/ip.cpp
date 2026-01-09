#include "lib/ip.hpp"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cassert>
#include <cstddef>
#include <cstdint>

#include "lib/types.hpp"
#include "packetline/constants.hpp"

#define HANDLE_OVERFLOW(view, sum)                                             \
  if (view) {                                                                  \
    sum += view;                                                               \
    view = 0;                                                                  \
  }

// Initial value should always be in host order.
uint16_t compute_ones_compliment(uint16_t initial_value, void *start,
                                 void *stop) {
  uint32_t cksum = initial_value;
  uint16_t *cksumv = (uint16_t *)&cksum;
  size_t s{0};

  // For each of the 16-bit values between start and stop,
  // sum them up!

  uint16_t *value_start{static_cast<uint16_t *>(start)};
  uint16_t *value_stop{static_cast<uint16_t *>(stop)};
  for (; value_start + s + 1 <= value_stop; s++) {
    cksum += ntohs(value_start[s]);
    HANDLE_OVERFLOW(cksumv[1], cksum);
  }

  // If the distance between start and stop is not a multiple of 2,
  // then there is a byte left that we have to consider!
  // Could have to pad!
  if ((value_start + s) < value_stop) {
    // In network order, the value to compute would look like
    // 0xVVPP
    // where PP is the padding. Make it so!
    uint16_t leftover{};
    uint8_t *upper_leftover = (uint8_t *)&leftover;
    *upper_leftover = *(uint8_t *)(value_start + s);
    cksum += ntohs(leftover);
    HANDLE_OVERFLOW(cksumv[1], cksum);
  }
  return cksum;
}

uint16_t compute_udp6_cksum(struct ip6_hdr *hdr, struct udphdr *udp,
                            data_p body) {

  // During computation, cksum is in host order.
  // Only at the end is it turned into network order.
  uint32_t cksum = 0;
  // cksumv is a 16-bit view over the 32-bit cksum (to use for detecting)
  // overflow.
  uint16_t *cksumv = (uint16_t *)&cksum;

  // The pseudoheader consists of  ...

  // 1. The source and destination IPv6 addresses.
  uint16_t *source = (uint16_t *)&hdr->ip6_src;
  cksum = compute_ones_compliment(0, source, source + 16);

  // 2. 32-bit length (of the udp header + body length)
  uint32_t length{
      htonl(static_cast<uint32_t>(sizeof(struct udphdr) + body.len))};
  uint16_t *lengthp{reinterpret_cast<uint16_t *>(&length)};
  cksum = compute_ones_compliment(cksum, lengthp, lengthp + 2);

  // 3. 3 bytes of zeroes.

  // 4. 1 byte for the UDP protocol value.
  // (Note: If we could guarantee that this was a little endian machine, we
  // would not need to be so cautious.)
  cksum += ntohs(htons(uint8_t(Pliney::UDP_PROTOCOL)));
  HANDLE_OVERFLOW(cksumv[1], cksum);

  // 5. The UDP header.
  cksum = compute_ones_compliment(cksum, udp, udp + 1);

  // 6. The body.
  cksum = compute_ones_compliment(cksum, body.data, body.data + body.len);

  return htons(~(cksum & 0xffff));
}

uint16_t compute_udp_cksum(Pliney::IpVersion type, void *ip, struct udphdr *udp,
                           data_p body) {
  if (type == Pliney::IpVersion::SIX) {
    return compute_udp6_cksum((struct ip6_hdr *)ip, udp, body);
  } else {
    assert(false);
  }
}

uint16_t compute_icmp_cksum(struct icmphdr *hdr, data_p body) {
  void *start{static_cast<void *>(hdr)};
  void *stop{static_cast<void *>(hdr + 1)};
  uint32_t cksum;
  uint16_t *cksumv = (uint16_t *)&cksum;
  cksum = compute_ones_compliment(0, start, stop);
  cksum = compute_ones_compliment(cksum, body.data, body.data + body.len);
  return htons(~(cksum & 0xffff));
}

// We assume no options!
uint16_t compute_ip4_cksum(struct iphdr *hdr) {
  void *start{static_cast<void *>(hdr)};
  void *stop{static_cast<void *>(hdr + 1)};
  uint32_t cksum;
  uint16_t *cksumv = (uint16_t *)&cksum;
  cksum = compute_ones_compliment(0, start, stop);
  return htons(~(cksum & 0xffff));
}

uint16_t compute_icmp6_cksum(struct ip6_hdr *hdr, struct icmp6_hdr *icmp,
                             data_p body) {

  // During computation, cksum is in host order.
  // Only at the end is it turned into network order.
  uint32_t cksum = 0;
  // cksumv is a 16-bit view over the 32-bit cksum (to use for detecting)
  // overflow.
  uint16_t *cksumv = (uint16_t *)&cksum;

  // The pseudoheader consists of  ...

  // 1. The source and destination IPv6 addresses.
  uint16_t *source = (uint16_t *)&hdr->ip6_src;
  cksum = compute_ones_compliment(0, source, source + 16);

  // 2. 32-bit length (of the udp header + body length)
  uint32_t length{htonl(
      static_cast<uint32_t>(Pliney::ICMP6_BASE_HEADER_LENGTH + body.len))};
  uint16_t *lengthp{reinterpret_cast<uint16_t *>(&length)};
  cksum = compute_ones_compliment(cksum, lengthp, lengthp + 2);

  // 3. 3 bytes of zeroes.

  // 4. 1 byte for the UDP protocol value.
  // (Note: If we could guarantee that this was a little endian machine, we
  // would not need to be so cautious.)
  cksum += ntohs(
      htons(uint8_t(Pliney::to_native_transport(Pliney::Transport::ICMP6))));
  HANDLE_OVERFLOW(cksumv[1], cksum);

  // 5. The ICMP header.
  cksum = compute_ones_compliment(
      cksum, icmp, (uint8_t *)icmp + Pliney::ICMP6_BASE_HEADER_LENGTH);

  // 6. The body.
  cksum = compute_ones_compliment(cksum, body.data, body.data + body.len);

  return htons(~(cksum & 0xffff));
}
