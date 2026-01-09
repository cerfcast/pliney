/* Copyright (c) John Millikin <john@john-millikin.com> */
/* SPDX-License-Identifier: 0BSD */

#ifndef _RUNNERS_XDP_NETLINK_H
#define _RUNNERS_XDP_NETLINK_H

#ifdef __cplusplus
extern "C" {
#endif

int netlink_connect();
int netlink_link_up(int netlink_fd, const char *iface_name);
int netlink_close(int netlink_fd);
int netlink_set_addr(int socket, const char *dev, struct sockaddr *addr);
int netlink_get_addr(int socket, const char *dev, struct sockaddr *addr);

#ifdef __cplusplus
}
#endif

#endif
