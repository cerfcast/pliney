#ifndef __PLINEY_IP_HPP
#define __PLINEY_IP_HPP

#include <cstdint>

#include "packetline/constants.hpp"
#include "lib/types.hpp"

namespace Pliney {
enum class IpVersion;
}  // namespace Pliney

uint16_t compute_udp_cksum(Pliney::IpVersion type, void *ip, struct udphdr *udp,
                           data_p body);
uint16_t compute_icmp_cksum(struct icmphdr *hdr, data_p body);
uint16_t compute_ip4_cksum(struct iphdr *hdr);
uint16_t compute_icmp6_cksum(struct ip6_hdr *hdr, struct icmp6_hdr *icmp,
                            data_p body);

#endif