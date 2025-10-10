#include "api/plugin.h"
#include "api/utils.h"
#include <fcntl.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

char *plugin_name = "raw";

enum mode { OVERWRITE, APPEND };

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  const char *filename = args[0];
  int flags = O_RDWR | O_APPEND;
  mode_t mode = 0;

  for (size_t arg = 0; arg < argc; arg++) {

#define HAS_ANOTHER_ARG                                                        \
  if (arg + 1 >= argc) {                                                       \
    char *err = (char *)calloc(255, sizeof(char));                             \
    snprintf(err, 255, "Missing argument for option %s", args[arg]);           \
    configuration_result.errstr = err;                                         \
    return configuration_result;                                               \
  } else {                                                                     \
    arg++;                                                                     \
  }

    if (!strcmp(args[arg], "-mode")) {
      HAS_ANOTHER_ARG;
      if (!strcmp(args[arg], "append")) {
        flags |= O_APPEND;
      } else if (!strcmp(args[arg], "overwrite")) {
        flags ^= O_APPEND;
        flags |= O_TRUNC | O_CREAT;
        mode = S_IRUSR | S_IWUSR | S_IRUSR;
      } else {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(
            err, 255,
            "Invalid overwrite/append configuration option (%s); values are "
            "append or overwrite",
            args[arg]);
        configuration_result.errstr = err;
        return configuration_result;
      }
    } else {
      filename = args[arg];
      break;
    }
  }

  int fd = open(filename, flags, mode);
  if (fd < 0) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255,
             "Could not open the file named %s (note: specify overwrite mode "
             "to create a file).",
             filename);
    configuration_result.errstr = err;
    return configuration_result;
  }

  int *fdp = (int *)calloc(1, sizeof(int));
  *fdp = fd;
  configuration_result.configuration_cookie = fdp;
  return configuration_result;
}

generate_result_t generate(packet_t *packet, void *cookie) {
  generate_result_t result = {.success = true};

  if (cookie != NULL) {
    int fd = *(int *)cookie;
    if (write(fd, packet->body.data, packet->body.len) < 0) {
      error("There was an error writing the packet to a file: %s",
            strerror(errno));
      result.success = false;
    }
  }

  return result;
}

cleanup_result_t cleanup(void *cookie) {
  cleanup_result_t result = {.success = true, .errstr = NULL};

  if (cookie != NULL) {
    int fd = *(int *)cookie;

    close(fd);

    free(cookie);
  }
  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  info->cleanup = cleanup;
  return true;
}