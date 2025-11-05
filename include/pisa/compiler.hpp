#ifndef _PIPELINE_EXECUTORS_HPP
#define _PIPELINE_EXECUTORS_HPP

#include "lib/pipeline.hpp"
#include "pisa/pisa.h"

#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <sys/socket.h>
#include <variant>

#include "compilation.hpp"
#include "packetline/runner.hpp"

class Compiler {
public:
  virtual CompilationResult compile(pisa_program_t *program,
                                    const Pipeline *pipeline) = 0;
  virtual ~Compiler() = default;
};

class BasicCompiler : public Compiler {
public:
  CompilationResult compile(pisa_program_t *program, const Pipeline *pipeline) override;
};

class CliCompiler : public BasicCompiler {
public:
  CompilationResult compile(pisa_program_t *program, const Pipeline *pipeline) override;
};

class XdpCompiler : public BasicCompiler {
public:
  CompilationResult compile(pisa_program_t *program, const Pipeline *pipeline) override;
};

using pipeline_executor_builder_t = std::function<
    std::pair<std::unique_ptr<Compiler>, std::unique_ptr<Runner>>()>;

class CompilerBuilder {
public:
  void with_name(const std::string &name, pipeline_executor_builder_t builder);
  std::variant<std::string,
               std::pair<std::unique_ptr<Compiler>, std::unique_ptr<Runner>>>
  by_name(const std::string &name);

private:
  std::map<std::string, pipeline_executor_builder_t> builders;
};

#endif