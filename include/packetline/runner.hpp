#ifndef _RESULT_EXECUTORS_HPP
#define _RESULT_EXECUTORS_HPP

#include <cstring>
#include <sys/socket.h>

#include "packetline/utilities.hpp"
#include "pisa/compilation.hpp"

class Runner {
public:
  virtual bool execute(Compilation &compilation) = 0;
  virtual ~Runner() = default;
};

class PacketRunner : public Runner {
public:
  bool execute(Compilation &compilation) override;
};

class PacketObserverRunner : public PacketRunner {
public:
  bool execute(Compilation &compilation) override;
};

class PacketSenderRunner : public PacketRunner {
public:
  bool execute(Compilation &) override;
};

class SocketBuilderRunner : public Runner {
public:
  bool execute(Compilation &compilation) override;
protected:
  int m_socket;
  std::optional<Swapsockopt<int>> m_ttlhl{};
  std::optional<Swapsockopt<int>> m_toss{};
  std::optional<std::unique_ptr<struct sockaddr, SockaddrDeleter>> m_destination;
  size_t m_destination_len{};
};

class CliRunner : public SocketBuilderRunner {
public:
  bool execute(Compilation &compilation) override;
};

class ForkRunner : public SocketBuilderRunner {
  using pisa_callback_t = void (*)(int, void *);
public:
  bool execute(Compilation &compilation) override;
};

class XdpRunner : public Runner {
public:
  bool execute(Compilation &compilation) override;
};

#endif
