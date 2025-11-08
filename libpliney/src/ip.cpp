#include "lib/ip.hpp"
#include "packetline/constants.hpp"
#include "pisa/types.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#define HANDLE_OVERFLOW(view, sum)                                             \
  if (view) {                                                                  \
    view = 0;                                                                  \
    sum += 1;                                                                  \
  }

uint16_t compute_ones_compliment(void *start, void *stop) {
  uint32_t cksum = 0;
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
  cksum = compute_ones_compliment(source, source + 16);

  // 2. 32-bit length (of the udp header + body length)
  uint32_t length{
      htonl(static_cast<uint32_t>(sizeof(struct udphdr) + body.len))};
  uint16_t *lengthp{reinterpret_cast<uint16_t *>(&length)};
  cksum += compute_ones_compliment(lengthp, lengthp + 2);
  HANDLE_OVERFLOW(cksumv[1], cksum);

  // 3. 3 bytes of zeroes.

  // 4. 1 byte for the UDP protocol value.
  // (Note: If we could guarantee that this was a little endian machine, we
  // would not need to be so cautious.)
  cksum += ntohs(htons(uint8_t(Pliney::UDP_PROTOCOL)));
  HANDLE_OVERFLOW(cksumv[1], cksum);

  // 5. The UDP header.
  cksum += compute_ones_compliment(udp, udp + 1);
  HANDLE_OVERFLOW(cksumv[1], cksum);

  // 6. The body.
  cksum += compute_ones_compliment(body.data, body.data + body.len);
  HANDLE_OVERFLOW(cksumv[1], cksum);

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
