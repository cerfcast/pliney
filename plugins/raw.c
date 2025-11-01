#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/types.h"
#include "pisa/utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

char *plugin_name = "raw";

enum mode { OVERWRITE, APPEND };

struct raw_args {
  enum mode mode;
  const char *filename;
};

bool parse_raw_args(int argc, const char **args, struct raw_args *parsed,
                    char **errstr) {
  for (size_t arg = 0; arg < argc; arg++) {

#define HAS_ANOTHER_ARG                                                        \
  if (arg + 1 >= argc) {                                                       \
    char *err = (char *)calloc(255, sizeof(char));                             \
    snprintf(err, 255, "Missing argument for option %s", args[arg]);           \
    *errstr = err;                                                             \
    return false;                                                              \
  } else {                                                                     \
    arg++;                                                                     \
  }

    if (!strcmp(args[arg], "-mode")) {
      HAS_ANOTHER_ARG;
      if (!strcmp(args[arg], "append")) {
        parsed->mode = APPEND;
      } else if (!strcmp(args[arg], "overwrite")) {
        parsed->mode = OVERWRITE;
      } else {
        char *err = (char *)calloc(255, sizeof(char));
        snprintf(
            err, 255,
            "Invalid overwrite/append configuration option (%s); values are "
            "append or overwrite",
            args[arg]);
        *errstr = err;
        return false;
      }
    } else {
      parsed->filename = args[arg];
      break;
    }
  }
  return true;
}

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  const char *filename = args[0];
  int flags = O_RDWR | O_APPEND;
  mode_t mode = 0;

  struct raw_args parsed_args;

  char *errstr = NULL;
  if (!parse_raw_args(argc, args, &parsed_args, &errstr)) {
    configuration_result.errstr = errstr;
    return configuration_result;
  }

  if (parsed_args.mode == OVERWRITE) {
    flags ^= O_APPEND;
    flags |= O_TRUNC | O_CREAT;
    mode = S_IRUSR | S_IWUSR | S_IRUSR;
  }

  int fd = open(parsed_args.filename, flags, mode);
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

void observe(pisa_program_t *program, packet_t *packet, void *cookie) {
  generate_result_t result = {.success = true};

  if (cookie != NULL) {
    int fd = *(int *)cookie;
    if (write(fd, packet->body.data, packet->body.len) < 0) {
      error("There was an error writing the packet to a file: %s",
            strerror(errno));
      result.success = false;
    }
  }
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

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "[-mode <overwrite, append>] <file path>";
  result.usage = 
  "Write the contents of the body of the packet to <file path>.\n"
  "Optionally specify a mode to determine how existing contents\n"
  "of <file path> are handled.";
  // clang-format on

  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = NULL;
  info->observer = observe;
  info->cleanup = cleanup;
  info->usage = usage;
  return true;
}