#ifndef _EXECUTORS_HPP
#define _EXECUTORS_HPP

#include "packetline/packetline.hpp"
#include "packetline/pipeline.hpp"
#include "packetline/utilities.hpp"

#include <cstring>
#include <memory>
#include <optional>
#include <sys/socket.h>
#include <variant>

using execution_context_t = std::variant<int, std::pair<std::string, std::string>>;

class PipelineExecutor {
public:
  virtual result_packet_tt execute(const Pipeline &plugins) = 0;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  explicit SerialPipelineExecutor(packet_t packet = {}) {
    m_initial_packet = packet;
    packet.header_extensions = {.extensions_count = 0,
                                .extensions_values = NULL};
  }

  result_packet_tt execute(const Pipeline &pipeline) override;

private:
  packet_t m_initial_packet{};
};

class NetworkExecutor {
public:
  virtual bool execute(execution_context_t execution_ctx, packet_t packet);
  virtual ~NetworkExecutor() = default;
};

class InterstitialNetworkExecutor : public NetworkExecutor {
public:
  bool execute(execution_context_t execution_ctx, packet_t packet) override;

  struct msghdr get_msg() const { return m_msg; }
  ~InterstitialNetworkExecutor();

private:
  struct msghdr m_msg{};
  struct iovec m_iov{};
  std::optional<std::unique_ptr<struct sockaddr, SockaddrDeleter>> m_destination{};
  std::optional<Swapsockopt<int>> m_toss;
};

class CliNetworkExecutor : public NetworkExecutor {
public:
  bool execute(execution_context_t execution_ctx, packet_t packet) override;
};

class XdpNetworkExecutor : public NetworkExecutor {
public:
  bool execute(execution_context_t execution_ctx, packet_t packet) override;
};

#endif
