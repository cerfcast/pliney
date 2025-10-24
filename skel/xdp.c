// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// clang-format on
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

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

  // We only handle IPv4 and IPv6 now.
  if (ethp->h_proto != htons(ETH_P_IP) && ethp->h_proto != htons(ETH_P_IPV6)) {
    return action;
  }

  if (ethp->h_proto == htons(ETH_P_IP)) {
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    CHECK_BREADTH(ip, data_end) { return XDP_PASS; }
    //__IPV4_PLINEY
    ip->check = compute_cksum(ip, data_end);
    return XDP_PASS;
  }

  struct ip6_hdr *ipv6 = (struct ip6_hdr *)(data + sizeof(struct ethhdr));
  CHECK_BREADTH(ipv6, data_end) { return XDP_PASS; }
  if (ethp->h_proto == htons(ETH_P_IPV6)) {
    //__IPV6_PLINEY
    return XDP_PASS;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
