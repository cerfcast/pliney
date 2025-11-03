#ifndef _RESULT_EXECUTORS_HPP
#define _RESULT_EXECUTORS_HPP

#include <cstring>
#include <sys/socket.h>

#include "pisa/compilation.hpp"

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

class XdpRunner : public Runner {
public:
  bool execute(CompilationResult &execution_ctx) override;
};

#endif
