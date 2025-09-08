#include "api/plugin.h"
#include "api/utils.h"
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

#define DEFAULT_BODY_SIZE 1500

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc < 1) {
    configuration_result.errstr = "Must provide a data file whose contents "
                                  "will be the body of the packet";
    return configuration_result;
  }

  uint32_t body_size = DEFAULT_BODY_SIZE;

  if (argc > 1) {
    char *invalid = NULL;
    uint32_t maybe_body_size = strtol(args[1], &invalid, 10);
    if (invalid && *invalid == '\0') {
      body_size = maybe_body_size;
    } else {
      char *err = (char *)calloc(255, sizeof(char));
      snprintf(
          err, 255,
          "Could not convert %s to a size for the number of bytes in the body",
          args[1]);
      configuration_result.errstr = err;
      return configuration_result;
    }
  }

  int fd = open(args[0], O_RDONLY);

  if (fd < 0) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not open data file (%s)", args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }

  // TODO: Make the number of bytes to read configurable.
  unsigned char *body_data = (unsigned char *)calloc(body_size, sizeof(char));
  int actual_body_size = read(fd, body_data, body_size);

  if (body_size != actual_body_size) {
    warn("Configured body size and actual body size did not match.\n");
  }

  body_p *body = (body_p *)malloc(sizeof(body_p));
  body->data = body_data;
  body->len = actual_body_size;

  configuration_result.configuration_cookie = body;

  return configuration_result;
}

generate_result_t generate(ip_addr_t source, ip_addr_t target,
                           extensions_p extensions, body_p body, void *cookie) {
  generate_result_t result;

  result.extensions = extensions;
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