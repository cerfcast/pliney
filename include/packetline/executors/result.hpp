#ifndef _RESULT_EXECUTORS_HPP
#define _RESULT_EXECUTORS_HPP

#include "packetline/executors/pipeline.hpp"
#include "packetline/utilities.hpp"

#include <cstring>
#include <memory>
#include <optional>
#include <sys/socket.h>

class ResultExecutor {
public:
  virtual bool execute(PipelineResult execution_ctx);
  virtual ~ResultExecutor() = default;
};

class InterstitialResultExecutor : public ResultExecutor {
public:
  bool execute(PipelineResult execution_ctx) override;

  struct msghdr get_msg() const { return m_msg; }
  ~InterstitialResultExecutor();

private:
  struct msghdr m_msg{};
  struct iovec m_iov{};
  std::optional<std::unique_ptr<struct sockaddr, SockaddrDeleter>>
      m_destination{};
  std::optional<Swapsockopt<int>> m_toss;
};

class CliResultExecutor : public ResultExecutor {
public:
  bool execute(PipelineResult execution_ctx) override;
};

#endif
