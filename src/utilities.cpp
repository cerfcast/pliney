#include <cstring>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <utility>

#include "packetline/constants.hpp"
#include "packetline/utilities.hpp"
#include "pisa/pisa.h"

bool operator==(const ip_addr_t &left, const ip_addr_t &right) {
  return !memcmp(&left, &right, sizeof(ip_addr_t));
}

std::unique_ptr<struct sockaddr, SockaddrDeleter>
unique_sockaddr(struct sockaddr *sin, size_t s) {
  return std::unique_ptr<struct sockaddr, SockaddrDeleter>{sin,
                                                           SockaddrDeleter(s)};
}

bool extend_cmsg(struct msghdr *mhdr, size_t additional_payload_len) {
  void *existing_cmsg_buf = mhdr->msg_control;
  size_t existing_cmsg_controllen = mhdr->msg_controllen;

  // Make new space that is bigger (enough to accommodate the new payload).
  mhdr->msg_controllen += CMSG_SPACE(additional_payload_len);
  mhdr->msg_control = (void *)calloc(mhdr->msg_controllen, sizeof(uint8_t));

  struct cmsghdr *nhdr = CMSG_FIRSTHDR(mhdr);
  // Set the length of the newly allocated header, but
  // leave all others blank for user to configure.
  nhdr->cmsg_len = CMSG_LEN(additional_payload_len);

  // Now, copy over the existing payload.
  nhdr = CMSG_NXTHDR(mhdr, nhdr);
  memcpy(nhdr, existing_cmsg_buf, existing_cmsg_controllen);

  // Finally, get rid of the old stuff!
  free(existing_cmsg_buf);

  return true;
}

size_t transport_header_size(Pliney::Transport transport) {
  switch (transport) {
    case Pliney::Transport::ICMP: {
      return Pliney::ICMP_BASE_HEADER_LENGTH;
    }
    case Pliney::Transport::ICMP6: {
      return Pliney::ICMP6_BASE_HEADER_LENGTH;
    }
    case Pliney::Transport::TCP: {
      return Pliney::TCP_BASE_HEADER_LENGTH;
    }
    case Pliney::Transport::UDP: {
      return Pliney::UDP_BASE_HEADER_LENGTH;
    }
  }
  std::unreachable();
}

size_t transport_has_port(Pliney::Transport transport) {
  switch (transport) {
    case Pliney::Transport::ICMP:
    case Pliney::Transport::ICMP6: {
      return false;
    }
    default:
      return true;
  }
}

bool is_protocol_transport(uint8_t native_ip_protocol) {
  return native_ip_protocol == Pliney::UDP_PROTOCOL ||
         native_ip_protocol == Pliney::TCP_PROTOCOL ||
         native_ip_protocol == Pliney::ICMP_PROTOCOL ||
         native_ip_protocol == Pliney::ICMP6_PROTOCOL;
}