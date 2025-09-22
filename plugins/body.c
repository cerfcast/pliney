#include "api/plugin.h"
#include "api/utils.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <memory.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

char *plugin_name = "body";

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc < 1) {
    configuration_result.errstr = "Must provide a data file whose contents "
                                  "will be the body of the packet";
    return configuration_result;
  }

  uint32_t body_size = 0;

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

  // If the user did not give a body size, infer it from a stat of the file.
  if (!body_size) {
    struct stat fd_stat;
    int fstat_result = fstat(fd, &fd_stat);

    if (fstat_result < 0) {
      close(fd);
      char *err = (char *)calloc(255, sizeof(char));
      snprintf(err, 255, "Could not stat data file (%s)", args[0]);
      configuration_result.errstr = err;
      return configuration_result;
    }
    body_size = fd_stat.st_size;
  }

  // Try to read all the data.
  unsigned char *body_data = (unsigned char *)calloc(body_size, sizeof(char));
  int read_body_size = read(fd, body_data, body_size);

  // If we got less data, alert the user.
  if (read_body_size < body_size) {
    warn("Expected body size %lu but could only read %lu; using "
         "%lu.\n",
         body_size, read_body_size, read_body_size);
    body_size = read_body_size;
  }

  body_p *body = (body_p *)malloc(sizeof(body_p));
  body->data = body_data;
  body->len = body_size;

  configuration_result.configuration_cookie = body;

  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    body_p *body = (body_p *)cookie;
    packet->body = *body;

    result.success = 1;
    free(cookie);

  } else {
    result.success = 0;
  }

  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  return true;
}
