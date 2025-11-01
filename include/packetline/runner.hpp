#ifndef _RESULT_EXECUTORS_HPP
#define _RESULT_EXECUTORS_HPP

#include "pisa/compiler.hpp"

#include <cstring>
#include <sys/socket.h>

class Runner {
public:
  virtual bool execute(CompilationResult &compilation) = 0;
  virtual ~Runner() = default;
};

class CliRunner : public Runner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

class PacketRunner : public Runner {
public:
  PacketRunner(const Pipeline &pipeline): m_pipeline{pipeline} {}
  bool execute(CompilationResult &execution_ctx) override;
private:
  const Pipeline &m_pipeline;
};

class XdpRunner : public Runner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

#endif
