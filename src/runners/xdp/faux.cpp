// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

#include "lib/logger.hpp"
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <packetline/runners/xdp/faux.h>
#include <packetline/runners/xdp/netlink.h>
#include <packetline/runners/xdp/xdpsupport.h>

#include <format>

#if 0
static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];
int sock;
#endif

static struct xdp_program *xdp_prog;
static u32 opt_batch_size = 64;

struct sockaddr_ll sockaddr_from_ethernet(const struct ether_header *ether,
                                          int rawi);

static void int_exit(int sig) {}

static void __exit_with_error(int error, const char *file, const char *func,
                              int line) {
  fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error,
          strerror(error));
  exit(EXIT_FAILURE);
}

#define exit_with_error(error)                                                 \
  __exit_with_error(error, __FILE__, __func__, __LINE__)
void faux_process_transport_ingress(struct xsk_socket_info *xsk, int ip_fd,
                                    process_packet_cb_t packet_processor) {

  u32 idx_rx = 0, idx_tx = 0, frags_done = 0;
  unsigned int rcvd, i, eop_cnt = 0;
  static u32 nb_frags;
  int ret;

  rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
  if (!rcvd) {
    xsk->app_stats.rx_empty_polls++;
    recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
    return;
  }

  ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
  while (ret != rcvd) {
    if (ret < 0)
      exit_with_error(-ret);
    ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
  }

  for (i = 0; i < rcvd; i++) {
    const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
    bool eop = IS_EOP_DESC(desc->options);
    u64 addr = desc->addr;
    u32 len = desc->len;
    u64 orig = addr;

    addr = xsk_umem__add_offset_to_addr(addr);
    char *pkt = (char *)xsk_umem__get_data(xsk->umem->buffer, addr);

    // If the packet is an IP packet, then we will do the work. Otherwise,
    // leave it alone.
    struct ether_header *eth = (struct ether_header *)pkt;
    if (eth->ether_type == htons(ETH_P_IP) || eth->ether_type == htons(ETH_P_IPV6)) {
      packet_processor(pkt, len);
    }

    if (write(ip_fd, pkt, len) < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR,
          std::format(
              "There was an error writing to the TAP interface: {}, {}.\n",
              errno, strerror(errno)));
    }

    Logger::ActiveLogger()->log(Logger::TRACE, "Forwarding down the tap ...");
    // xdp_hex_dump(pkt, len, addr);
  }

  xsk_ring_cons__release(&xsk->rx, frags_done);

  xsk->ring_stats.rx_npkts += eop_cnt;
  xsk->ring_stats.tx_npkts += eop_cnt;
  xsk->ring_stats.rx_frags += rcvd;
  xsk->ring_stats.tx_frags += rcvd;
  xsk->outstanding_tx += frags_done;
}

int faux_alloc_transport(const char *dev_to_ape_name, int idx) {
  int raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  if (raw < 0) {
    return -1;
  }

  struct sockaddr_ll sl;

  memset(&sl, 0, sizeof(struct sockaddr_ll));
  sl.sll_ifindex = idx;
  sl.sll_family = PF_PACKET;
  sl.sll_protocol = htons(ETH_P_ALL);
  if (bind(raw, (struct sockaddr *)&sl, sizeof(struct sockaddr_ll)) < 0) {
    return -1;
  }
  return raw;
}

struct sockaddr_ll sockaddr_from_ethernet(const struct ether_header *ether,
                                          int rawi) {
  struct sockaddr_ll result_ll;

  memset(&result_ll, 0, sizeof(struct sockaddr_ll));
  result_ll.sll_family = AF_PACKET;
  memcpy(&result_ll.sll_addr, &ether->ether_dhost, ETH_ALEN);

  result_ll.sll_ifindex = rawi;
  result_ll.sll_halen = ETH_ALEN;
  result_ll.sll_protocol = htons(IPPROTO_ETHERNET);

  return result_ll;
}

void *faux_process_transport_egress(void *config) {

  Logger::ActiveLogger()->log(Logger::DEBUG,
                              "Starting the tap egress processor...");
  faux_process_transport_egress_config_t *tap_handler_config =
      (faux_process_transport_egress_config_t *)config;

  while (tap_handler_config->keep_going) {
    char buffer[1500];
    int just_read = read(tap_handler_config->ip_fd, buffer, 1500);
    if (just_read < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR,
          std::format("Error reading from tunnel: {}", strerror(errno)));
    }

    Logger::ActiveLogger()->log(
        Logger::TRACE, std::format("Got {} bytes to egress.\n", just_read));

    struct ether_header *ether = (struct ether_header *)buffer;

    if (ether->ether_type == htons(ETH_P_IP) || ether->ether_type == htons(ETH_P_IPV6)) {
      tap_handler_config->packet_processor(ether, just_read);
    }

    struct sockaddr_ll outgoing_address =
        sockaddr_from_ethernet(ether, tap_handler_config->transport_iface_idx);

    int just_wrote = sendto(tap_handler_config->transport_fd, buffer, just_read, 0,
                            (struct sockaddr *)&outgoing_address,
                            sizeof(struct sockaddr_ll));
    if (just_wrote < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR, std::format("Error sending out egress interface: {}",
                                     strerror(errno)));
    }
  }

  return NULL;
}

int faux_alloc_ip(const char *reqd_tap_name, const char *aped_dev_name) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR, O_NONBLOCK)) < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("There was an error creating the tun/tap interface: {}\n",
                    strerror(errno)));
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if (*reqd_tap_name)
    strncpy(ifr.ifr_name, reqd_tap_name, IFNAMSIZ);

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }

  // Note: It is possible that the ioctl changed the name from underneath us ...
  // we are not going to handle that right now.

  // Now, up the link.
  int nl = netlink_connect();
  if (nl < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("There was an error getting the netlink socket: {}\n",
                    strerror(errno)));
    return -1;
  }

  if (netlink_link_up(nl, reqd_tap_name) < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("There was an error up'ng the tap interface: {}\n",
                    strerror(errno)));
    return -1;
  }

  struct sockaddr aperaddr;
  if (netlink_get_addr(nl, aped_dev_name, &aperaddr) < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format(
            "There was an error getting the address of the link to ape: {}\n",
            strerror(errno)));
    return -1;
  }

  /*
  printf("existing address: ");
  for (size_t i = 0; i < 14; i++) {
    printf("0x%2x", (unsigned char)aperaddr.sa_data[i]);
  }
  printf("\n");
  */

  if (netlink_set_addr(fd, reqd_tap_name, &aperaddr) < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("There was an error setting the address of the tap: {}\n",
                    strerror(errno)));
    return -1;
  }

  if (netlink_close(nl) < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("There was an error closing the netlink socket: {}\n",
                    strerror(errno)));
    return -1;
  }
  return fd;
}