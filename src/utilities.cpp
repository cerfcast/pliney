#include <cstring>

#include "packetline/utilities.hpp"

bool operator==(const ip_addr_t &left, const ip_addr_t &right) {
  return !memcmp(&left, &right, sizeof(ip_addr_t));
}
