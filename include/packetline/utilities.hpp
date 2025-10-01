#ifndef __UTILITIES_HPP
#define __UTILITIES_HPP

#include "api/plugin.h"
#include <cstdlib>
#include <memory>
#include <sys/socket.h>

bool operator==(const ip_addr_t &left, const ip_addr_t &right);

struct SockaddrDeleter {
public:
  SockaddrDeleter(size_t s) : m_size(s) {}

  void operator()(void *todelete) {
    if (m_size == sizeof(struct sockaddr_in)) {
      struct sockaddr_in *in = static_cast<struct sockaddr_in *>(todelete);
      free(in);

    } else if (m_size == sizeof(struct sockaddr_in)) {
      struct sockaddr_in6 *in6 = static_cast<struct sockaddr_in6 *>(todelete);
      free(in6);
    };
  };

private:
  size_t m_size;
};

std::unique_ptr<struct sockaddr, SockaddrDeleter>
unique_sockaddr(struct sockaddr *sin, size_t s);

#endif
