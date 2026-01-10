// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

#ifndef __RUNNERS_XDP_FAUX_H
#define __RUNNERS_XDP_FAUX_H

#include "packetline/runners/xdp/xdpsupport.h"

#include <functional> // IWYU pragma: export
typedef std::function<void*(void *, size_t, size_t*)> process_packet_cb_t;

void faux_process_transport_ingress(struct xsk_socket_info *xsk, int ip_fd,
                         process_packet_cb_t packet_processor);

/*
 * Allocate handles for the faux IP and transport interfaces.
 */
int faux_alloc_ip(const char *to_make, const char *to_ape);
int faux_alloc_transport(const char *transport_dev_name, int transport_idx);

typedef struct {
  // A file descriptor to the IP (TAP) interface.
  int ip_fd;
  int transport_fd;
  int transport_iface_idx;
  volatile bool *keep_going;
  process_packet_cb_t packet_processor;
} faux_process_transport_egress_config_t;

void *faux_process_transport_egress(void *);

#endif