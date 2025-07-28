#ifndef _UTILS_H
#define _UTILS_H

#include "plugin.h"

#ifdef __cplusplus
extern "C" {
#endif
int ip_to_sockaddr(ip_addr_t addr, struct sockaddr **result);
int ip_to_socket(ip_addr_t addr);

#ifdef __cplusplus
}
#endif
#endif