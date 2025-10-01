#ifndef _EXECUTORS_HPP
#define _EXECUTORS_HPP

#include "packetline/packetline.hpp"
#include "packetline/pipeline.hpp"
#include "packetline/utilities.hpp"

#include <cstring>
#include <memory>
#include <optional>
#include <sys/socket.h>

class PipelineExecutor {
public:
  virtual result_packet_tt execute(Pipeline &&plugins) = 0;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  explicit SerialPipelineExecutor(packet_t packet = {}) {
    m_initial_packet = packet;
    packet.header_extensions = {.extensions_count = 0,
                                .extensions_values = NULL};
  }

  result_packet_tt execute(Pipeline &&pipeline) override;

private:
  packet_t m_initial_packet{};
  std::optional<Pipeline> m_pipeline;
};

class NetworkExecutor {
public:
  virtual bool execute(int socket, int connection_type, packet_t packet);
};

class InterstitialNetworkExecutor : public NetworkExecutor {
public:
  bool execute(int socket, int connection_type, packet_t packet);

  struct msghdr get_msg() const { return m_msg; }

private:
  struct msghdr m_msg{};
  struct iovec m_iov{};
};

class CliNetworkExecutor : public NetworkExecutor {
public:
  bool execute(int socket, int connection_type, packet_t packet);
};

#endif
