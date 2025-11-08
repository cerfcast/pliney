#ifndef __LIB_IP_HPP
#define __LIB_IP_HPP

#include "packetline/constants.hpp"
#include "lib/types.h"
#include <cstdint>

uint16_t compute_udp_cksum(Pliney::IpVersion type, void *ip, struct udphdr *udp,
                           data_p body);
#endif