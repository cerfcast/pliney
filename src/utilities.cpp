#include <cstring>
#include <utility>

#include "packetline/constants.hpp"
#include "packetline/utilities.hpp"

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
      return Pliney::ICMP_DEFAULT_HEADER_LENGTH;
    }
    case Pliney::Transport::TCP: {
      return Pliney::TCP_DEFAULT_HEADER_LENGTH;
    }
    case Pliney::Transport::UDP: {
      return Pliney::UDP_DEFAULT_HEADER_LENGTH;
    }
  }
  std::unreachable();
}

size_t transport_has_port(Pliney::Transport transport) {
  switch (transport) {
    case Pliney::Transport::ICMP: {
      return false;
    }
    default:
      return true;
  }
}
