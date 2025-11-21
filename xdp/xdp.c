// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// clang-format on
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>

// #define TESTING

#define CHECK_BREADTH(st, end) CHECK_BREADTH_MULTIPLE(st, 1, end)
#define CHECK_BREADTH_MULTIPLE(st, mult, end) if (((void *)(st + mult)) > end)

__attribute__((always_inline)) uint16_t compute_cksum(struct iphdr *ip,
                                                      void *ip_end) {
  uint32_t cksum = 0;
  uint8_t *cksumv = (uint8_t *)&cksum;

  uint16_t *headerb = (uint16_t *)ip;

  CHECK_BREADTH_MULTIPLE(headerb, 10, ip_end) { return XDP_PASS; }

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

SEC("xdp")
int pliney_xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  /* Default action XDP_PASS, imply everything we couldn't parse, or that
   * we don't want to deal with, we just pass up the stack and let the
   * kernel deal with it.
   */
  __u32 action = XDP_PASS; /* Default action */

  /* These keep track of the next header type and iterator pointer */
  struct ethhdr *ethp = data;
  CHECK_BREADTH(ethp, data_end) { return XDP_PASS; }

  // Whichever is non-null is the mode we are in!
  struct iphdr *ip = NULL;
  struct ip6_hdr *ipv6 = NULL;

  uint8_t ethernet_mode = 1;

  //__ETHERNET_MODE_PLINEY
#ifdef TESTING
  ethernet_mode = 0;
#endif

  if (ethernet_mode) {
    // We only handle IPv4 and IPv6 now.
    if (ethp->h_proto != htons(ETH_P_IP) &&
        ethp->h_proto != htons(ETH_P_IPV6)) {
      return XDP_PASS;
    }

    // Now that we know it is an IP packet, find out which version.
    if (ethp->h_proto == htons(ETH_P_IP)) {
      ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    } else {
      ipv6 = (struct ip6_hdr *)(data + sizeof(struct ethhdr));
    }
  } else {
    // Assume that we are are in raw IP mode.
    struct iphdr *maybe_ip = (struct iphdr *)(data);
    CHECK_BREADTH(maybe_ip, data_end) { return XDP_PASS; }

    // Now that we found _an_ IP packet, find out which version.
    if (maybe_ip->version == 0x4) {
      ip = maybe_ip;
    } else {
      ipv6 = (struct ip6_hdr *)(data);
    }
  }

  if (ip) {
    CHECK_BREADTH(ip, data_end) { return XDP_PASS; }

    //__IPV4_PLINEY

#ifdef TESTING
    set_ecn_v4(ip, IPTOS_ECN_ECT1);
    set_dscp_v4(ip, IPTOS_DSCP_AF21);
    ip->ttl = 2;
#endif
    ip->check = compute_cksum(ip, data_end);
    return XDP_PASS;
  }

  if (ipv6) {
    CHECK_BREADTH(ipv6, data_end) { return XDP_PASS; }
    //__IPV6_PLINEY
#ifdef TESTING
    set_ecn_v6(ipv6, IPTOS_ECN_ECT1);
    set_dscp_v6(ipv6, IPTOS_DSCP_AF21);
    ipv6->ip6_hlim = 2;
#endif
    return XDP_PASS;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
