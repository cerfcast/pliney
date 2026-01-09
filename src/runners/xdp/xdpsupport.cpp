// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

// IWYU pragma: no_include <asm/int-ll64.h>
#include <arpa/inet.h>
#include <errno.h>
#include <endian.h>
#include <linux/types.h>
#include <stdint.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <xdp/xsk.h>
#include <packetline/runners/xdp/xdpsupport.h>

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

void xdp_apply_setsockopt(struct xsk_socket_info *xsk) {
  int sock_opt;

  sock_opt = 1;
  if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
                 (void *)&sock_opt, sizeof(sock_opt)) < 0)
    exit_with_error(errno);

  sock_opt = 20;
  if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
                 (void *)&sock_opt, sizeof(sock_opt)) < 0)
    exit_with_error(errno);

  sock_opt = opt_batch_size;
  if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
                 (void *)&sock_opt, sizeof(sock_opt)) < 0)
    exit_with_error(errno);
}

void xdp_cleanup_sock(struct xsk_socket_info *xsk) {
  struct xsk_umem *umem = xsk->umem->umem;
  int i, cmd = CLOSE_CONN;

  xsk_socket__delete(xsk->xsk);
  (void)xsk_umem__delete(umem);
}

struct xsk_umem_info *xdp_xsk_configure_umem(void *buffer, u64 size) {
  struct xsk_umem_info *umem;
  struct xsk_umem_config cfg = {
      /* We recommend that you set the fill ring size >= HW RX ring size +
       * AF_XDP RX ring size. Make sure you fill up the fill ring
       * with buffers at regular intervals, and you will with this setting
       * avoid allocation failures in the driver. These are usually quite
       * expensive since drivers have not been written to assume that
       * allocation failures are common. For regular sockets, kernel
       * allocated memory is used that only runs out in OOM situations
       * that should be rare.
       */
      .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
      .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
      .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
      .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
      .flags = 0};
  int ret;

  umem = (struct xsk_umem_info *)calloc(1, sizeof(*umem));
  if (!umem)
    exit_with_error(errno);

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
  if (ret)
    exit_with_error(-ret);

  umem->buffer = buffer;
  return umem;
}

void xsk_populate_fill_ring(struct xsk_umem_info *umem) {
  int ret, i;
  u32 idx;

  ret = xsk_ring_prod__reserve(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
                               &idx);
  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
    exit_with_error(-ret);
  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
    *xsk_ring_prod__fill_addr(&umem->fq, idx++) =
        i * XSK_UMEM__DEFAULT_FRAME_SIZE;
  xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
}

struct xsk_socket_info *xdp_xsk_configure_socket(struct xsk_umem_info *umem,
                                                 const char *ifname, bool rx,
                                                 bool tx) {
  struct xsk_socket_config cfg;
  struct xsk_socket_info *xsk;
  struct xsk_ring_cons *rxr;
  struct xsk_ring_prod *txr;
  int ret;

  xsk = (struct xsk_socket_info *)calloc(1, sizeof(*xsk));
  if (!xsk)
    exit_with_error(errno);

  xsk->umem = umem;
  cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  // cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
  cfg.libxdp_flags = 0;
  cfg.xdp_flags = XDP_FLAGS_SKB_MODE;

  cfg.bind_flags = XDP_USE_NEED_WAKEUP;

  rxr = rx ? &xsk->rx : NULL;
  txr = tx ? &xsk->tx : NULL;
  ret = xsk_socket__create(&xsk->xsk, ifname, 0, umem->umem, rxr, txr, &cfg);
  if (ret)
    exit_with_error(-ret);

  xsk->app_stats.rx_empty_polls = 0;
  xsk->app_stats.fill_fail_polls = 0;
  xsk->app_stats.copy_tx_sendtos = 0;
  xsk->app_stats.tx_wakeup_sendtos = 0;
  xsk->app_stats.opt_polls = 0;
  xsk->app_stats.prev_rx_empty_polls = 0;
  xsk->app_stats.prev_fill_fail_polls = 0;
  xsk->app_stats.prev_copy_tx_sendtos = 0;
  xsk->app_stats.prev_tx_wakeup_sendtos = 0;
  xsk->app_stats.prev_opt_polls = 0;

  return xsk;
}

void xdp_hex_dump(void *pkt, size_t length, u64 addr) {
  const unsigned char *address = (unsigned char *)pkt;
  const unsigned char *line = address;
  size_t line_size = 32;
  unsigned char c;
  char buf[32];
  int i = 0;

  sprintf(buf, "addr=%llu", addr);
  printf("length = %zu\n", length);
  printf("%s | ", buf);
  while (length-- > 0) {
    printf("%02X ", *address++);
    if (!(++i % line_size) || (length == 0 && i % line_size)) {
      if (length == 0) {
        while (i++ % line_size)
          printf("__ ");
      }
      printf(" | "); /* right close */
      while (line < address) {
        c = *line++;
        printf("%c", (c < 33 || c == 255) ? 0x2E : c);
      }
      printf("\n");
      if (length > 0)
        printf("%s | ", buf);
    }
  }
  printf("\n");
}

static void *memset32_htonl(void *dest, u32 val, u32 size) {
  u32 *ptr = (u32 *)dest;
  int i;

  val = htonl(val);

  for (i = 0; i < (size & (~0x3)); i += 4)
    ptr[i >> 2] = val;

  for (; i < size; i++)
    ((char *)dest)[i] = ((char *)&val)[i & 3];

  return dest;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x) {
  /* add up 16-bit and 16-bit for 16+c bit */
  x = (x & 0xffff) + (x >> 16);
  /* add up carry.. */
  x = (x & 0xffff) + (x >> 16);
  return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len) {
  unsigned int result = 0;
  int odd;

  if (len <= 0)
    goto out;
  odd = 1 & (unsigned long)buff;
  if (odd) {
#ifdef __LITTLE_ENDIAN
    result += (*buff << 8);
#else
    result = *buff;
#endif
    len--;
    buff++;
  }
  if (len >= 2) {
    if (2 & (unsigned long)buff) {
      result += *(unsigned short *)buff;
      len -= 2;
      buff += 2;
    }
    if (len >= 4) {
      const unsigned char *end = buff + ((unsigned int)len & ~3);
      unsigned int carry = 0;

      do {
        unsigned int w = *(unsigned int *)buff;

        buff += 4;
        result += carry;
        result += w;
        carry = (w > result);
      } while (buff < end);
      result += carry;
      result = (result & 0xffff) + (result >> 16);
    }
    if (len & 2) {
      result += *(unsigned short *)buff;
      buff += 2;
    }
  }
  if (len & 1)
#ifdef __LITTLE_ENDIAN
    result += *buff;
#else
    result += (*buff << 8);
#endif
  result = from32to16(result);
  if (odd)
    result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
  return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
uint16_t ip_fast_csum(const unsigned char *iph, unsigned int ihl) {
  return (uint16_t)~do_csum(iph, ihl * 4);
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum) {
  u32 sum = (u32)csum;

  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline u32 from64to32(u64 x) {
  /* add up 32-bit and 32-bit for 32+c bit */
  x = (x & 0xffffffff) + (x >> 32);
  /* add up carry.. */
  x = (x & 0xffffffff) + (x >> 32);
  return (u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len, __u8 proto,
                          __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len, __u8 proto,
                          __wsum sum) {
  unsigned long long s = (u32)sum;

  s += (u32)saddr;
  s += (u32)daddr;
#ifdef __BIG_ENDIAN__
  s += proto + len;
#else
  s += (proto + len) << 8;
#endif
  return (__wsum)from64to32(s);
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
                                        __u8 proto, __wsum sum) {
  return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline u16 udp_csum(u32 saddr, u32 daddr, u32 len, u8 proto,
                           u16 *udp_pkt) {
  u32 csum = 0;
  u32 cnt = 0;

  /* udp hdr and data */
  for (; cnt < len; cnt += 2)
    csum += udp_pkt[cnt >> 1];

  return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}
