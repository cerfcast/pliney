#ifndef _PIPELINE_EXECUTORS_HPP
#define _PIPELINE_EXECUTORS_HPP

#include "pisa/pipeline.hpp"
#include "pisa/pisa.h"

#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <sys/socket.h>
#include <variant>

struct CompilationResult {
  bool success{false};
  std::string error{};
  pisa_program_t *program{};
  packet_t packet;

  static CompilationResult Success(pisa_program_t *program) {
    return CompilationResult{.success = true, .error = "", .program = program};
  }
  static CompilationResult Failure(std::string error) {
    return CompilationResult{.success = false, .error = error, .program = nullptr};
  }

  ~CompilationResult() {
    if (packet.ip.data != nullptr) {
      free(packet.ip.data );
      packet.ip.data = nullptr;
      packet.ip.len = 0;
      packet.transport.data = nullptr;
      packet.transport.len = 0;

      // Because the body comes from a plugin, that's not our problem!
    }
    pisa_program_release(program);
  }
};

class Compiler {
public:
  virtual CompilationResult compile(pisa_program_t *program, const Pipeline &pipeline) = 0;
  virtual ~Compiler() = default;
};

class BasicCompiler : public Compiler {
public:
  CompilationResult compile(pisa_program_t *program, const Pipeline &pipeline);
};

class CliCompiler : public BasicCompiler {
public:
  CompilationResult compile(pisa_program_t *program, const Pipeline &pipeline);
};

class XdpCompiler : public BasicCompiler {
public:
  CompilationResult compile(pisa_program_t *program, const Pipeline &pipeline);
};

using pipeline_executor_builder_t =
    std::function<std::unique_ptr<Compiler>()>;

class CompilerBuilder {
public:
  void with_name(const std::string &name, pipeline_executor_builder_t builder);
  std::variant<std::string, std::unique_ptr<Compiler>>
  by_name(const std::string &name);

private:
  std::map<std::string, pipeline_executor_builder_t> builders;
};

#endif