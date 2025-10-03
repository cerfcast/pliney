#include <arpa/inet.h>
#include <assert.h>
#include <bits/types/struct_iovec.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>

int main(int argc, char **argv) {

  int s = -1;

  if (argc > 1) {
    if (!strcmp(argv[1], "ipv6")) {
      s = socket(AF_INET6, SOCK_DGRAM, 0);
    } else {
      printf("error: Only ipv6 is allowed as an argument to %s.", argv[0]);
      return -1;
    }
  } else {
    s = socket(AF_INET, SOCK_DGRAM, 0);
  }
  assert(s >= 0);

  char body[50] = {
      0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,
      0xb,  0xc,  0xd,  0xe,  0xf,  0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
      0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
      0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
  };

  struct sockaddr_storage saddr;
  socklen_t saddr_len = 0;
  memset(&saddr, 0, sizeof(struct sockaddr_storage));

  if (argc > 1) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof(struct sockaddr_in6);
    int inet_pton_result =
        inet_pton(AF_INET6, "fd7a:115c:a1e0::5fa2:3b13", &sin6->sin6_addr);
    sin6->sin6_port = htons(53);
    sin6->sin6_family = AF_INET6;
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in *)&saddr;
    saddr_len = sizeof(struct sockaddr_in);
    int inet_pton_result = inet_pton(AF_INET, "8.8.8.8", &sin->sin_addr);
    sin->sin_port = htons(53);
    sin->sin_family = AF_INET;
  }

  int r = -1;
  if (argc > 1) {
    struct msghdr hdr;
    hdr.msg_name = (void *)&saddr;
    hdr.msg_namelen = saddr_len;
    struct iovec iov;
    hdr.msg_iov = &iov;

    hdr.msg_iov->iov_base = body;
    hdr.msg_iov->iov_len = sizeof(body);
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;

    r = sendmsg(s, &hdr, 0);
    if (r < 0) {
      printf("error: %s\n", strerror(errno));
    }
  } else {
    r = sendto(s, body, sizeof(body), 0, (const struct sockaddr *)&saddr,
               saddr_len);
  }
  assert(r >= 0);

  close(s);

  return 0;
}