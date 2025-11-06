#include "lib/ip.hpp"
#include "lib/pipeline.hpp"
#include "packetline/constants.hpp"
#include "packetline/runner.hpp"
#include "pisa/compiler.hpp"

#include "lib/logger.hpp"
#include "packetline/utilities.hpp"
#include "pisa/pisa.h"
#include "pisa/plugin.h"
#include "pisa/types.h"

#include <cstring>
#include <fstream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "luasocket/luasocket.h"
}

// Keep in sync with t_udp in
// luasocket/src/udp.h.
struct lua_udp {
  int socket;
  struct {
    double block;
    double total;
    double start;
  } timeout;
  int family;
};

bool LuaForkRunner::execute(CompilationResult &execution_ctx) {

  if (!execution_ctx.success || !execution_ctx.program) {
    return false;
  }

  auto program = execution_ctx.program;

  pisa_value_t pisa_lua_source_file{.tpe = PTR};

  // Now, find out the transport type. The program must set one.
  if (!pisa_program_find_meta_value(program, "LUA_SOURCE",
                                    &pisa_lua_source_file)) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, "Could not find the name of the XDP output file!");
    return false;
  }

  auto lua_source_path =
      std::filesystem::path((char *)pisa_lua_source_file.value.ptr.data);

  std::string lua_source_code{};

  std::ifstream lua_source_fs{lua_source_path};

  // Read the entire skeleton file.
  char lua_source_code_just_read{};
  lua_source_fs >> std::noskipws;
  while (lua_source_fs >> lua_source_code_just_read) {
    lua_source_code += lua_source_code_just_read;
  }

  SocketBuilderRunner::execute(execution_ctx);
  if (!execution_ctx.success || !execution_ctx.program) {
    return false;
  }

  if (connect(m_socket, m_destination->get(), m_destination_len) < 0) {
    Logger::ActiveLogger()->log(Logger::ERROR, "Could not connect the socket.");
  }

  lua_State *lstate = luaL_newstate();
  luaL_openlibs(lstate);

  luaL_requiref(lstate, "socket", luaopen_socket_core, 1);

  lua_pop(lstate, 1);

  struct lua_udp *lua_udp_socket =
      (struct lua_udp *)lua_newuserdata(lstate, sizeof(struct lua_udp));
  lua_udp_socket->socket = m_socket;
  lua_udp_socket->family = AF_INET;
  lua_udp_socket->timeout.block = -1;
  lua_udp_socket->timeout.total = -1;
  luaL_getmetatable(lstate, "udp{connected}");
  lua_setmetatable(lstate, -2);

  lua_setglobal(lstate, "PLINEY_SOCKET");

  if (luaL_loadstring(lstate, lua_source_code.c_str()) == LUA_OK) {
    if (lua_pcall(lstate, 0, 0, 0) == LUA_OK) {
      // If it was executed successfuly we
      // remove the code from the stack
      lua_pop(lstate, lua_gettop(lstate));
    }
  }

  lua_close(lstate);
  return true;
}
