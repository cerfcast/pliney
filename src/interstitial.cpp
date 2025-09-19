#include <asm-generic/socket.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <netinet/in.h>
#include <numeric>
#include <optional>
#include <sys/socket.h>

#include "api/plugin.h"
#include "api/utils.h"
#include "packetline/executors.hpp"
#include "packetline/logger.hpp"
#include "packetline/pipeline.hpp"

#include <dlfcn.h>

static bool configured = false;
static std::optional<Pipeline> maybe_pipeline{};

__attribute__((constructor)) void pliney_initialize() {
  printf("About to initialize plineyi\n");

  auto plugin_path = std::filesystem::path("./build");
  auto plugins = PluginDir{plugin_path};
  auto loaded_plugins = plugins.plugins();

  auto logger = Logger::ActiveLogger();
  logger->set_level(Logger::DEBUG);

  char *user_pipeline = getenv("PLINEY_PIPELINE");

  if (user_pipeline) {
    auto pipeline = Pipeline{user_pipeline, std::move(loaded_plugins)};

    if (pipeline.ok()) {
      maybe_pipeline = pipeline;
    } else {
      auto pipeline_errs = std::accumulate(
          pipeline.error_begin(), pipeline.error_end(), std::string{},
          [](const std::string existing, const std::string next) {
            if (existing.length()) {
              return existing + "; " + next;
            }
            return next;
          });
      Logger::ActiveLogger()->log(
          Logger::ERROR,
          std::format("Error occurred configuring pipeline: {}\n",
                      pipeline_errs));
      return;
    }
  } else {
    Logger::ActiveLogger()->log(Logger::WARN, "No pliney pipeline found.");
  }
  configured = true;
}

typedef ssize_t (*sendto_pt)(int sockfd, const void *buff, size_t len,
                             int flags, const struct sockaddr *dest,
                             socklen_t dest_len);
typedef ssize_t (*sendmsg_pt)(int sockfd, const struct msghdr *msghdr,
                              int flags);

ssize_t sendto(int sockfd, const void *buff, size_t len, int flags,
               const struct sockaddr *dest, socklen_t dest_len) {
  static auto orig_sendto = (sendto_pt)dlsym(RTLD_NEXT, "sendto");

  if (!orig_sendto) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the original sendto.");
    return -1;
  }

  if (!maybe_pipeline) {
    Logger::ActiveLogger()->log(Logger::WARN, "No pliney pipeline to execute.");
    return orig_sendto(sockfd, buff, len, flags, dest, dest_len);
  }

  // Get the type of the socket.
  uint32_t connection_type = 0;
  socklen_t connection_type_size = sizeof(uint32_t);
  int result = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &connection_type,
                          &connection_type_size);

  if (connection_type == SOCK_DGRAM) {
    connection_type = INET_DGRAM;
  } else {
    connection_type = INET_STREAM;
  }

  // Get the destination address.
  ip_addr_t dest_pliney_addr;
  result = sockaddr_to_ip(dest, dest_len, &dest_pliney_addr);

  packet_t initial_packet{};

  initial_packet.body = body_p{.len = len, .data = (uint8_t *)buff};
  initial_packet.target = dest_pliney_addr;

  auto executor = SerialPipelineExecutor{initial_packet};
  auto maybe_result = executor.execute(std::move(*maybe_pipeline));

  if (std::holds_alternative<packet_t>(maybe_result)) {
    auto actual_result = std::get<packet_t>(maybe_result);

    auto netexec = InterstitialNetworkExecutor();
    netexec.execute(sockfd, connection_type, actual_result);
  } else {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Error occurred executing the pipeline: {}\n",
                    std::get<std::string>(maybe_result)));
  }

  return orig_sendto(sockfd, buff, len, flags, dest, dest_len);
}

ssize_t sendmsg(int sockfd, const struct msghdr *hdr, int flags) {
  static auto orig_sendmsg = (sendmsg_pt)dlsym(RTLD_NEXT, "sendmsg");

  if (!orig_sendmsg) {
    Logger::ActiveLogger()->log(Logger::ERROR,
                                "Could not find the original sendmsg.");
    return -1;
  }

  if (!maybe_pipeline) {
    Logger::ActiveLogger()->log(Logger::WARN, "No pliney pipeline to execute.");
    return orig_sendmsg(sockfd, hdr, flags);
  }

  // Get the type of the socket.
  uint32_t connection_type = 0;
  socklen_t connection_type_size = sizeof(uint32_t);
  int result = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &connection_type,
                          &connection_type_size);

  if (connection_type == SOCK_DGRAM) {
    connection_type = INET_DGRAM;
  } else {
    connection_type = INET_STREAM;
  }

  packet_t initial_packet{};

  // Assume that the body has only one iov.
  // TODO: Handle bodies that are longer.
  initial_packet.body = body_p{.len = hdr->msg_iov->iov_len,
                               .data = (uint8_t *)hdr->msg_iov->iov_base};

  if (hdr->msg_name != 0) {
    // Get the destination address.
    ip_addr_t dest_pliney_addr;
    result = sockaddr_to_ip((const struct sockaddr *)hdr->msg_name,
                            hdr->msg_namelen, &dest_pliney_addr);

    initial_packet.target = dest_pliney_addr;
  }

  auto executor = SerialPipelineExecutor{initial_packet};
  auto maybe_result = executor.execute(std::move(*maybe_pipeline));

  if (std::holds_alternative<packet_t>(maybe_result)) {
    auto actual_result = std::get<packet_t>(maybe_result);

    auto netexec = InterstitialNetworkExecutor();
    netexec.execute(sockfd, connection_type, actual_result);

    struct msghdr new_msghdr = netexec.get_msg();

    return orig_sendmsg(sockfd, &new_msghdr, flags);

  } else {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Error occurred executing the pipeline: {}\n",
                    std::get<std::string>(maybe_result)));
  }

  return orig_sendmsg(sockfd, hdr, flags);
}