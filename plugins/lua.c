#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/priority.h"
#include "pisa/types.h"
#include "pisa/utils.h"
#include <asm-generic/socket.h>
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

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "luasocket/luasocket.h"
struct lua_timeout {
  double block;
  double total;
  double start;
};

typedef struct t_io_ {
  void *ctx;   /* context needed by send/recv */
  void *send;  /* send function pointer */
  void *recv;  /* receive function pointer */
  void *error; /* strerror function */
} lua_io;

typedef struct {
  double birthday;       /* throttle support info: creation time, */
  size_t sent, received; /* bytes sent, and bytes received */
  lua_io *io;            /* IO driver used for this buffer */
  struct lua_timeout tm; /* timeout management for this buffer */
  size_t first, last;    /* index of first and last bytes of stored data */
  char data[8192];       /* storage space for buffer data */
} lua_buffer;

// Keep in sync with t_udp in
// luasocket/src/udp.h.
struct lua_udp {
  int socket;
  struct lua_timeout timeout;
  int family;
};

struct lua_tcp {
  int sock;
  lua_io io;
  lua_buffer buf;
  struct {
    double block;
    double total;
    double start;
  } timeout;
  int family;
};

char *plugin_name = "lua";

configuration_result_t generate_configuration(int argc, const char **args) {
  configuration_result_t configuration_result = {.configuration_cookie = NULL,
                                                 .errstr = NULL};

  if (argc < 1) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Lua plugin did not get a path to a source code file.");
    configuration_result.errstr = err;
    return configuration_result;
  }

  int fd = open(args[0], O_RDONLY);

  if (fd < 0) {
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not open source code file (%s)", args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }

  // If the user did not give a body size, infer it from a stat of the file.
  size_t body_size;
  struct stat fd_stat;
  int fstat_result = fstat(fd, &fd_stat);

  if (fstat_result < 0) {
    close(fd);
    char *err = (char *)calloc(255, sizeof(char));
    snprintf(err, 255, "Could not stat lua source code file (%s)", args[0]);
    configuration_result.errstr = err;
    return configuration_result;
  }
  body_size = fd_stat.st_size + 1;

  // Try to read all the data.
  unsigned char *body_data = (unsigned char *)calloc(body_size, sizeof(char));
  int read_body_size = read(fd, body_data, body_size);

  data_p *source = (data_p *)malloc(sizeof(data_p));
  source->data = body_data;
  source->len = body_size;

  configuration_result.configuration_cookie = source;

  return configuration_result;
}

void do_lua_exec(int socket, void *cookie) {
  data_p *source_data = (data_p *)cookie;

  // First, we have to get the protocol (either UDP or TCP).
  int protocol = 0;
  socklen_t protocol_size = sizeof(protocol);
  if (getsockopt(socket, SOL_SOCKET, SO_PROTOCOL, &protocol, &protocol_size) <
      0) {
    error("Could not get the socket option!");
    return;
  }

  lua_State *lstate = luaL_newstate();
  luaL_openlibs(lstate);

  luaL_requiref(lstate, "socket", luaopen_socket_core, 1);

  lua_pop(lstate, 1);

  if (protocol == IPPROTO_UDP) {
    struct lua_udp *lua_udp_socket =
        (struct lua_udp *)lua_newuserdata(lstate, sizeof(struct lua_udp));
    lua_udp_socket->socket = socket;
    lua_udp_socket->family = AF_INET;
    lua_udp_socket->timeout.block = -1;
    lua_udp_socket->timeout.total = -1;
    luaL_getmetatable(lstate, "udp{connected}");
    lua_setmetatable(lstate, -2);
  } else {

    lua_getglobal(lstate, "socket");
    lua_getfield(lstate, -1, "tcp");
    lua_call(lstate, 0, 1);
    struct lua_tcp *lua_tcp_socket =
        (struct lua_tcp *)lua_touserdata(lstate, 0);

    lua_tcp_socket->sock = socket;
    lua_tcp_socket->family = AF_INET;
    luaL_getmetatable(lstate, "tcp{client}");
    lua_setmetatable(lstate, -2);
  }

  lua_setglobal(lstate, "PLINEY_SOCKET");

  if (luaL_loadstring(lstate, (const char *)source_data->data) == LUA_OK) {
    if (lua_pcall(lstate, 0, 0, 0) == LUA_OK) {
      lua_pop(lstate, lua_gettop(lstate));
    }
  }

  lua_close(lstate);
}

generate_result_t generate(pisa_program_t *program, void *cookie) {
  generate_result_t result;

  if (cookie != NULL) {
    data_p *body = (data_p *)cookie;

    pisa_inst_t set_body_inst;
    set_body_inst.op = EXEC;
    set_body_inst.value.tpe = CALLBACK;
    set_body_inst.value.value.callback.callback = (void *)do_lua_exec;
    set_body_inst.value.value.callback.cookie = cookie;
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
  result.params = "<FILE_PATH>";
  result.usage = 
  "With the socket configured according to the pipeline (seen\n"
  "so far, execute the lua code contained in FILE_PATH. The\n"
  "socket variable is _G.PLINEY_SOCKET.";
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
