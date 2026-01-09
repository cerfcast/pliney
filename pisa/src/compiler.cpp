#include <format>
#include <memory>
#include <functional>
#include <iterator>
#include <map>
#include <string>
#include <utility>
#include <variant>

#include "lib/logger.hpp"
#include "pisa/compiler.hpp"
#include "pisa/compilation.hpp"
#include "pisa/plugin.h"
#include "lib/pipeline.hpp"
#include "packetline/invocation.hpp"
#include "pisa/plugin.hpp"

class Runner;

Compilation BasicCompiler::compile(unique_pisa_program_t program,
                                         const Pipeline *pipeline) {

  for (auto invocation : *pipeline) {
    auto result = invocation.plugin.generate(program.get(), invocation.cookie);

    if (std::holds_alternative<generate_result_t>(result)) {
      Logger::ActiveLogger().log(Logger::DEBUG,
                                  std::format("Got a result from '{}' plugin!",
                                              invocation.plugin.name()));
      generate_result_t x = std::get<generate_result_t>(result);
    } else {
      return Compilation::Failure(std::format(
          "There was an error: {}\n", std::get<std::string>(result)), std::move(program));
    }
  }

  return Compilation::Success(std::move(program), pipeline);
}

Compilation CliCompiler::compile(unique_pisa_program_t program,
                                       const Pipeline *pipeline) {
  return BasicCompiler::compile(std::move(program), pipeline);
}

Compilation XdpCompiler::compile(unique_pisa_program_t program,
                                       const Pipeline *pipeline) {
  return BasicCompiler::compile(std::move(program), pipeline);
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
