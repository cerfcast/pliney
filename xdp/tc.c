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

#include "process.h"

#ifdef TESTING
#include "process.c"
#endif

//__PROCESS_PLINEY

SEC("egress")
int pliney_egress(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  /* These keep track of the next header type and iterator pointer */
  struct ethhdr *ethp = data;
  CHECK_BREADTH(ethp, data_end) { return TC_ACT_OK; }

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
      return TC_ACT_OK;
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
    CHECK_BREADTH(maybe_ip, data_end) { return TC_ACT_OK; }

    // Now that we found _an_ IP packet, find out which version.
    if (maybe_ip->version == 0x4) {
      ip = maybe_ip;
    } else {
      ipv6 = (struct ip6_hdr *)(data);
    }
  }

  if (ip) {
    CHECK_BREADTH(ip, data_end) { return TC_ACT_OK; }
    return pliney_process_v4(ip, TC_ACT_OK, TC_ACT_DROP);
  }

  if (ipv6) {
    CHECK_BREADTH(ipv6, data_end) { return TC_ACT_OK; }
    return pliney_process_v6(ipv6, TC_ACT_OK, TC_ACT_DROP);
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
