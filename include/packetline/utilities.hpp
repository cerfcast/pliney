#ifndef __UTILITIES_HPP
#define __UTILITIES_HPP

#include "pisa/types.h"
#include <cstdlib>
#include <memory>
#include <sys/socket.h>

#include <iostream>

bool operator==(const ip_addr_t &left, const ip_addr_t &right);

struct SockaddrDeleter {
public:
  SockaddrDeleter(size_t s) : m_size(s) {}

  void operator()(void *todelete) {
    if (m_size == sizeof(struct sockaddr_in)) {
      struct sockaddr_in *in = static_cast<struct sockaddr_in *>(todelete);
      free(in);

    } else if (m_size == sizeof(struct sockaddr_in6)) {
      struct sockaddr_in6 *in6 = static_cast<struct sockaddr_in6 *>(todelete);
      free(in6);
    };
  };

private:
  size_t m_size;
};

std::unique_ptr<struct sockaddr, SockaddrDeleter>
unique_sockaddr(struct sockaddr *sin, size_t s);

template <typename T> class Swapsockopt {
public:
  Swapsockopt(int socket, int level, int optname, T value, T merge = 0)
      : m_socket(socket), m_level(level), m_optname(optname), m_current(),
        m_valuel(sizeof(T)), m_existingl(sizeof(T)) {

    int result{-1};

    result =
        getsockopt(m_socket, m_level, m_optname, &m_existing, &m_existingl);
    if (result < 0) {
      m_success = false;
    }

    m_current = m_existing;

    again(value, merge);
  }

  bool ok() const { return m_success; }

  void again(T value, T merge) {
    T value_to_set{value};

    if (merge) {
      value_to_set = m_current & ~merge;
      value_to_set |= value;
    }

    int result =
        setsockopt(m_socket, m_level, m_optname, &value_to_set, m_valuel);

    if (result < 0) {
      m_success = false;
    }
    m_current = value_to_set;
    m_success = true;
  }

  ~Swapsockopt() {
    if (!ok()) {
      return;
    }

    int result{-1};
    result = setsockopt(m_socket, m_level, m_optname, &m_existing, m_existingl);

    if (result < 0) {
      m_success = false;
    }
    m_success = true;
  }

private:
  int m_socket;
  int m_level;
  int m_optname;
  T m_current;
  T m_existing;
  socklen_t m_valuel;
  socklen_t m_existingl;
  bool m_success;
};

bool extend_cmsg(struct msghdr *mhdr, size_t additional_payload_len);

#endif