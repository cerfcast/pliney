#ifndef _RESULT_EXECUTORS_HPP
#define _RESULT_EXECUTORS_HPP

#include <cstring>
#include <sys/socket.h>

#include "packetline/utilities.hpp"
#include "pisa/compilation.hpp"

class Runner {
public:
  virtual bool execute(CompilationResult &compilation) = 0;
  virtual ~Runner() = default;
};

class PacketRunner : public Runner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

class PacketObserverRunner : public PacketRunner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

class PacketSenderRunner : public PacketRunner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

class SocketBuilderRunner : public Runner {
public:
  bool execute(CompilationResult &execution_ctx) override;
protected:
  int m_socket;
  std::optional<Swapsockopt<int>> m_ttlhl{};
  std::optional<Swapsockopt<int>> m_toss{};
  std::optional<std::unique_ptr<struct sockaddr, SockaddrDeleter>> m_destination;
  size_t m_destination_len{};
};

class CliRunner : public SocketBuilderRunner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

class LuaForkRunner : public SocketBuilderRunner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

class XdpRunner : public Runner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

#endif
