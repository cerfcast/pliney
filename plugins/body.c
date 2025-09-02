#include "api/plugin.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <memory.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int load() {
  printf("Loaded body plugin!\n");
  return 1;
}

char *plugin_name = "body";

char *name() { return plugin_name; }

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  int fd = open(args[0], O_RDONLY);

  if (fd < 0) {
    configuration_result.errstr = "Could not open data file";
    return configuration_result;
  }

  unsigned char *body_data = (unsigned char *)calloc(50, sizeof(char));
  int body_size = read(fd, body_data, 50);

  body_p *body = (body_p *)malloc(sizeof(body_p));
  body->data = body_data;
  body->len = body_size;

  configuration_result.configuration_cookie = body;

  return configuration_result;
}

generate_result_t generate(ip_addr_t source, ip_addr_t target, body_p body,
                           void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    body_p *body = (body_p *)cookie;
    result.destination = target;
    result.source = source;
    result.body = *body;

    result.success = 1;
    free(cookie);

  } else {
    result.success = 0;
  }

  return result;
}