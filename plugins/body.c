#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

char *plugin_name = "body";

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc < 1) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Body plugin got no argument.");
    configuration_result.errstr = err;
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

  data_p *body = (data_p *)malloc(sizeof(data_p));
  body->data = body_data;
  body->len = body_size;

  configuration_result.configuration_cookie = body;

  return configuration_result;
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    data_p *body = (data_p *)cookie;

    pisa_inst_t set_body_inst;
    set_body_inst.op = SET_FIELD;
    set_body_inst.fk.field = BODY;
    set_body_inst.value.tpe = PTR;
    set_body_inst.value.value.ptr.data = body->data;
    set_body_inst.value.value.ptr.len = body->len;
    result.success = pisa_program_add_inst(program, &set_body_inst);

    result.success = 1;

  } else {
    result.success = 0;
  }

  return result;
}

cleanup_result_t cleanup(void *cookie) {
  if (cookie != NULL) {
    data_p *body = (data_p *)cookie;
    free(body->data);
    free(cookie);
  }

  cleanup_result_t result = {.success = true, .errstr = NULL};
  return result;
}

usage_result_t usage() {
  usage_result_t result;

  // clang-format off
  result.params = "<FILE_PATH> [SIZE]";
  result.usage = 
  "Replace the existing body of the packet with the contents of\n"
  "FILE_PATH. SIZE (in bytes), if given, caps the size of the\n"
  "new body. If SIZE is not specified, the entire contents of\n"
  "FILE_PATH will be used.";
  // clang-format on

  return result;
}

bool load(plugin_t *info) {
  info->name = plugin_name;
  info->configurator = generate_configuration;
  info->generator = generate;
  info->cleanup = cleanup;
  info->usage = usage;
  return true;
}
