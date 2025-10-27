#ifndef _PIPELINE_EXECUTORS_HPP
#define _PIPELINE_EXECUTORS_HPP

#include "api/plugin.h"
#include "packetline/pipeline.hpp"

#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <sys/socket.h>
#include <variant>

using execution_context_t =
    std::variant<int, std::pair<std::string, std::string>>;

struct PipelineResult {
  int socket;
  bool needs_network;
  std::optional<packet_t> packet;
  std::optional<std::string> error;
  bool success;

  static PipelineResult Failure(std::optional<std::string> error = {}) {
    return PipelineResult{.socket = -1,
                          .needs_network = false,
                          .packet = {},
                          .error = error,
                          .success = false};
  }

  static PipelineResult Success(std::optional<packet_t> packet = {}) {
    return PipelineResult{.socket = -1,
                          .needs_network = false,
                          .packet = packet,
                          .error = {},
                          .success = true};
  }
};

class PipelineExecutor {
public:
  virtual PipelineResult execute(packet_t initial_packet,
                                 const Pipeline &plugins) = 0;
  virtual ~PipelineExecutor() = default;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  PipelineResult execute(packet_t initial_packet,
                         const Pipeline &pipeline) override;
};

class NetworkSerialPipelineExecutor : public SerialPipelineExecutor {
public:
  PipelineResult execute(packet_t initial_packet,
                         const Pipeline &pipeline) override;
};

class XdpPipelineExecutor : public SerialPipelineExecutor {
public:
  PipelineResult execute(packet_t initial_packet,
                         const Pipeline &pipeline) override;
};

using pipeline_executor_builder_t =
    std::function<std::unique_ptr<PipelineExecutor>()>;

class PipelineExecutorBuilder {
public:
  void with_name(const std::string &name, pipeline_executor_builder_t builder);
  std::variant<std::string, std::unique_ptr<PipelineExecutor>>
  by_name(const std::string &name);

private:
  std::map<std::string, pipeline_executor_builder_t> builders;
};

#endif