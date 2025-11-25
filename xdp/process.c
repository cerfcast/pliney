#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "process.h"

__attribute__((always_inline)) uint16_t compute_cksum(struct iphdr *ip,
                                                      void *ip_end) {
  uint32_t cksum = 0;
  uint8_t *cksumv = (uint8_t *)&cksum;

  uint16_t *headerb = (uint16_t *)ip;

  CHECK_BREADTH_MULTIPLE(headerb, 10, ip_end) { return 0; }

  cksum += headerb[0];
  cksum += headerb[1];
  cksum += headerb[2];
  cksum += headerb[3];
  cksum += headerb[4];
  ///
  cksum += headerb[6];
  cksum += headerb[7];
  cksum += headerb[8];
  cksum += headerb[9];

  cksum += cksumv[2] & 0xf;

  return ~(cksum & 0xffff);
}

void set_ecn_v4(struct iphdr *ip, uint8_t ecn_value) {
  ip->tos &= ~(0x03);
  ip->tos |= ecn_value;
}
void set_ecn_v6(struct ip6_hdr *ip, uint8_t ecn_value) {
  ip->ip6_flow &= ~(htonl(0x3 << 20));
  ip->ip6_flow |= htonl(ecn_value << 20);
}
void set_dscp_v4(struct iphdr *ip, uint8_t dscp_value) {
  ip->tos &= ~(0xfc);
  ip->tos |= dscp_value;
}
void set_dscp_v6(struct ip6_hdr *ip, uint8_t dscp_value) {
  ip->ip6_flow &= ~(htonl(0xfc << 20));
  ip->ip6_flow |= htonl(dscp_value << 20);
}

__attribute__((always_inline)) int
pliney_process_v6(struct ip6_hdr *ipv6, int good_result, int bad_result) {

  //__IPV6_PLINEY

#ifdef TESTING
  set_ecn_v6(ipv6, IPTOS_ECN_ECT1);
  set_dscp_v6(ipv6, IPTOS_DSCP_AF21);
  ipv6->ip6_hlim = 2;
#endif

  return good_result;
}

__attribute__((always_inline)) int
pliney_process_v4(struct iphdr *ip, int good_result, int bad_result) {

  //__IPV4_PLINEY

#ifdef TESTING
  set_ecn_v4(ip, IPTOS_ECN_ECT1);
  set_dscp_v4(ip, IPTOS_DSCP_AF21);
  ip->ttl = 2;
#endif
  ip->check = compute_cksum(ip, ip + 1);

  return good_result;
}
