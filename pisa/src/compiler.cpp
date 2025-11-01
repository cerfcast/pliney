#include "pisa/compiler.hpp"
#include "pisa/pipeline.hpp"
#include "packetline/logger.hpp"

#include "pisa/plugin.h"
#include "pisa/pisa.h"

#include <cstring>
#include <format>
#include <netinet/in.h>
#include <sys/socket.h>

CompilationResult BasicCompiler::compile(pisa_program_t *program, const Pipeline &pipeline) {

  for (auto invocation : pipeline) {
    auto result = invocation.plugin.generate(program, invocation.cookie);

    if (std::holds_alternative<generate_result_t>(result)) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  std::format("Got a result from '{}' plugin!",
                                              invocation.plugin.name()));
      generate_result_t x = std::get<generate_result_t>(result);
    } else {
      return CompilationResult::Failure(std::format(
          "There was an error: {}\n", std::get<std::string>(result)));
    }
  }

  return CompilationResult::Success(program);
}

CompilationResult
CliCompiler::compile(pisa_program_t *program, const Pipeline &pipeline) {
  return BasicCompiler::compile(program, pipeline);
}

CompilationResult XdpCompiler::compile(pisa_program_t *program,
                                            const Pipeline &pipeline) {
  return BasicCompiler::compile(program, pipeline);

  #if 0
  if (!packet_pipeline_result.success) {
    return packet_pipeline_result;
  }

  auto packet = *packet_pipeline_result.packet;

  auto xdp_path = std::filesystem::path("./skel/xdp.c");
  auto xdp_output_path = std::filesystem::path("./build/pliney_xdp.c");

  std::ifstream xdp_skel{xdp_path};

  if (!xdp_skel) {
    packet_pipeline_result.error = "Could not access the XDP program skeleton.";
    return packet_pipeline_result;
  }

  std::ofstream xdp_output_skel{xdp_output_path, std::ios::trunc};
  if (!xdp_output_skel) {
    packet_pipeline_result.error = "Could not access the XDP output file.";
    return packet_pipeline_result;
  }

  // Read the entire skeleton file.
  std::string xdp_skel_contents{};
  char xdp_skel_just_read{};
  xdp_skel >> std::noskipws;
  while (xdp_skel >> xdp_skel_just_read) {
    xdp_skel_contents += xdp_skel_just_read;
  }

  // Generate the xdp code.
  std::string xdp_ipv4_code{};
  std::string xdp_ipv6_code{};
  if (packet.target.family == INET_ADDR_V4) {
    if (packet.header.ttl) {
      xdp_ipv4_code += std::format("ip->ttl = {};\n", packet.header.ttl);
    }
  } else if (packet.target.family == INET_ADDR_V6) {
    xdp_ipv6_code += std::format("ipv6->ip6_hlim = {};\n", packet.header.ttl);
  }

  // Emit the xdp source code.
  std::regex skel_ip_regex{"//__IPV4_PLINEY"};
  std::regex skel_ipv6_regex{"//__IPV6_PLINEY"};
  xdp_skel_contents =
      std::regex_replace(xdp_skel_contents, skel_ip_regex, xdp_ipv4_code);
  xdp_skel_contents =
      std::regex_replace(xdp_skel_contents, skel_ipv6_regex, xdp_ipv6_code);
  xdp_output_skel << xdp_skel_contents;

  packet_pipeline_result.success = true;
  packet_pipeline_result.needs_network = false;

  return packet_pipeline_result;
  #endif
}

void CompilerBuilder::with_name(const std::string &name,
                                        pipeline_executor_builder_t builder) {
  builders[name] = builder;
}

std::variant<std::string, std::unique_ptr<Compiler>>
CompilerBuilder::by_name(const std::string &name) {

  if (builders.contains(name)) {
    return std::variant<std::string, std::unique_ptr<Compiler>>{
        std::move(builders[name]())};
  }

  return std::format("No builder named {} is registered.", name);
}
