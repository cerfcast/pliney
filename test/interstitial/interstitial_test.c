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
    s = socket(AF_INET6, SOCK_DGRAM, 0);
  } else {
    s = socket(AF_INET, SOCK_DGRAM, 0);
  }
  assert(s >= 0);

  char body[50] = {
      0,
  };

  struct sockaddr_storage saddr;
  socklen_t saddr_len = 0;
  memset(&saddr, 0, sizeof(struct sockaddr_storage));

  if (argc > 1) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof(struct sockaddr_in6);
    int inet_pton_result =
        inet_pton(AF_INET6, "fd7a:115c:a1e0::5fa2:3b13", &sin6->sin6_addr);
    sin6->sin6_port = 53;
    sin6->sin6_family = AF_INET6;
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in *)&saddr;
    saddr_len = sizeof(struct sockaddr_in);
    int inet_pton_result = inet_pton(AF_INET, "8.8.8.8", &sin->sin_addr);
    sin->sin_port = 53;
    sin->sin_family = AF_INET;
  }

  int r = -1;
  if (argc > 1) {
    struct msghdr hdr;
    hdr.msg_name = (void*)&saddr;
    hdr.msg_namelen = saddr_len;
    struct iovec iov;
    hdr.msg_iov = &iov;

    hdr.msg_iov->iov_base = body;
    hdr.msg_iov->iov_len = sizeof(body);
    hdr.msg_iovlen = 1;

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