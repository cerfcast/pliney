#include "lib/logger.hpp"
#include "pisa/compiler.hpp"
#include "pisa/compilation.hpp"

#include "pisa/pisa.h"
#include "pisa/plugin.h"

#include <cstring>
#include <format>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>

CompilationResult BasicCompiler::compile(pisa_program_t *program,
                                         const Pipeline *pipeline) {

  for (auto invocation : *pipeline) {
    auto result = invocation.plugin.generate(program, invocation.cookie);

    if (std::holds_alternative<generate_result_t>(result)) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  std::format("Got a result from '{}' plugin!",
                                              invocation.plugin.name()));
      generate_result_t x = std::get<generate_result_t>(result);
    } else {
      return CompilationResult::Failure(std::format(
          "There was an error: {}\n", std::get<std::string>(result)), program);
    }
  }

  return CompilationResult::Success(program, pipeline);
}

CompilationResult CliCompiler::compile(pisa_program_t *program,
                                       const Pipeline *pipeline) {
  return BasicCompiler::compile(program, pipeline);
}

CompilationResult XdpCompiler::compile(pisa_program_t *program,
                                       const Pipeline *pipeline) {
  return BasicCompiler::compile(program, pipeline);
}

void CompilerBuilder::with_name(const std::string &name,
                                pipeline_executor_builder_t builder) {
  builders[name] = builder;
}

std::variant<std::string,
             std::pair<std::unique_ptr<Compiler>, std::unique_ptr<Runner>>>
CompilerBuilder::by_name(const std::string &name) {

  if (builders.contains(name)) {
    return std::variant < std::string,
           std::pair<std::unique_ptr<Compiler>, std::unique_ptr<Runner>>>{
               std::move(builders[name]())};
  }

  return std::format("No builder named {} is registered.", name);
}
