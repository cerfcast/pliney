#include "packetline/executors/pipeline.hpp"
#include "packetline/logger.hpp"

#include "api/plugin.h"
#include "api/utils.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <regex>
#include <sys/socket.h>

PipelineResult SerialPipelineExecutor::execute(packet_t initial_packet,
                                               const Pipeline &pipeline) {

  auto packet = initial_packet;

  for (auto invocation : pipeline) {

    auto result = invocation.plugin.generate(&packet, invocation.cookie);

    if (std::holds_alternative<generate_result_t>(result)) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  std::format("Got a result from '{}' plugin!",
                                              invocation.plugin.name()));
      generate_result_t x = std::get<generate_result_t>(result);
    } else {
      return PipelineResult::Failure(std::format(
          "There was an error: {}\n", std::get<std::string>(result)));
    }
  }

  return PipelineResult::Success(packet);
}

PipelineResult
NetworkSerialPipelineExecutor::execute(packet_t initial_packet,
                                       const Pipeline &pipeline) {

  auto packet_pipeline_result =
      SerialPipelineExecutor::execute(initial_packet, pipeline);

  if (!packet_pipeline_result.success) {
    return packet_pipeline_result;
  }

  auto packet = *packet_pipeline_result.packet;
  auto skt = ip_to_socket(packet.target, packet.transport);
  if (skt < 0) {
    packet_pipeline_result.error = std::format(
        "Error occurred sending data: could not open the socket: \n",
        strerror(errno));
    return packet_pipeline_result;
  }

  packet_pipeline_result.socket = skt;
  packet_pipeline_result.success = true;
  packet_pipeline_result.needs_network = true;

  return packet_pipeline_result;
}

PipelineResult XdpPipelineExecutor::execute(packet_t initial_packet,
                                            const Pipeline &pipeline) {

  auto packet_pipeline_result =
      SerialPipelineExecutor::execute(initial_packet, pipeline);

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
}
