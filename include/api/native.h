#ifndef _NATIVE_H
#define _NATIVE_H

#include "api/plugin.h"
#include <netinet/ip.h>


bool to_native_packet(uint8_t type, packet_t , void **, size_t *);


#endif