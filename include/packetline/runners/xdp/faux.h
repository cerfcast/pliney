// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

#ifndef __FAUX_H
#define __FAUX_H

#include "packetline/runners/xdp/xdpsupport.h"
#include <functional>


typedef std::function<void(void *, size_t)> process_packet_cb_t;

void faux_process_transport_ingress(struct xsk_socket_info *xsk, int tapfd,
                         process_packet_cb_t packet_processor);

/*
 * Allocate handles for the faux IP and transport interfaces.
 */

int faux_alloc_ip(const char *dev, const char *ip_dev_name);
int faux_alloc_transport(const char *transport_dev_name);

typedef struct {
  int tunfd;
  int rawfd;
  int rawi;
  volatile bool *keep_going;
  process_packet_cb_t packet_processor;
} faux_process_transport_egress_config_t;

void *faux_process_transport_egress(void *);

#endif