#include <cstring>

#include "packetline/utilities.hpp"

bool operator==(const ip_addr_t &left, const ip_addr_t &right) {
  return !memcmp(&left, &right, sizeof(ip_addr_t));
}

std::unique_ptr<struct sockaddr, SockaddrDeleter>
unique_sockaddr(struct sockaddr *sin, size_t s) {
  return std::unique_ptr<struct sockaddr, SockaddrDeleter>{sin,
                                                           SockaddrDeleter(s)};
}
