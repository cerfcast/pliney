/* Copyright (c) John Millikin <john@john-millikin.com> */
/* SPDX-License-Identifier: 0BSD */
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_arp.h>

#include "packetline/runners/xdp/netlink.h"

int netlink_connect() {
	int netlink_fd, rc;
	struct sockaddr_nl sockaddr;

	netlink_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (netlink_fd == -1) {
		return -1;
	}

	memset(&sockaddr, 0, sizeof sockaddr);
	sockaddr.nl_family = AF_NETLINK;
	rc = bind(netlink_fd, (struct sockaddr*) &sockaddr, sizeof sockaddr);
	if (rc == -1) {
		int bind_errno = errno;
		close(netlink_fd);
		errno = bind_errno;
		return -1;
	}
	return netlink_fd;
}

int netlink_link_up(int netlink_fd, const char *iface_name) {
	struct {
		struct nlmsghdr  header;
		struct ifinfomsg content;
	} request;

	memset(&request, 0, sizeof request);
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof request.content);
	request.header.nlmsg_flags = NLM_F_REQUEST;
	request.header.nlmsg_type = RTM_NEWLINK;
	request.content.ifi_index = if_nametoindex(iface_name);
	request.content.ifi_flags = IFF_UP;
	request.content.ifi_change = 1;

	if (send(netlink_fd, &request, request.header.nlmsg_len, 0) == -1) {
		return -1;
	}
	return 0;
}

int netlink_close(int netlink_fd) {
	return close(netlink_fd);
}

int netlink_get_addr(int socket, const char *dev, struct sockaddr *addr) {
	struct ifreq res;
	memset(&res, 0, sizeof(struct ifreq));
	res.ifr_hwaddr.sa_family = ARPHRD_ETHER;

	memset(addr, 0, sizeof(struct sockaddr));

	strncpy(res.ifr_name, dev, IFNAMSIZ);

	if (ioctl(socket, SIOCGIFHWADDR, &res)) {
		printf("Error performing GET ioctl.\n");
		return -1;
	}

	memcpy(addr, &res.ifr_hwaddr, sizeof(struct sockaddr));
	return 0;
}
	
int netlink_set_addr(int socket, const char *dev, struct sockaddr *addr) {
	struct ifreq res;

	strncpy(res.ifr_name, dev, IFNAMSIZ);
	memcpy(&res.ifr_hwaddr, addr, sizeof(struct sockaddr));

	if (ioctl(socket, SIOCSIFHWADDR, &res)) {
		printf("Error performing SET ioctl.\n");
		return -1;
	}

	return 0;
}
