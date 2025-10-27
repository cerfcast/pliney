#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <format>
#include <netinet/in.h>
#include <optional>
#include <sys/socket.h>
#include <variant>

#include "api/exthdrs.h"
#include "api/plugin.h"
#include "api/utils.h"
#include "packetline/executors/pipeline.hpp"
#include "packetline/executors/result.hpp"
#include "packetline/logger.hpp"
#include "packetline/packetline.hpp"
#include "packetline/pipeline.hpp"

extern bool configured;
extern std::optional<Pipeline> maybe_pipeline;

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

  if (result < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, "Could not get the connection type using getsockopt.");
    return orig_sendto(sockfd, buff, len, flags, dest, dest_len);
  }

  if (connection_type == SOCK_DGRAM) {
    connection_type = INET_DGRAM;
  } else if (connection_type == SOCK_STREAM) {
    connection_type = INET_STREAM;
  } else {
    Logger::ActiveLogger()->log(
        Logger::ERROR, "Connection type was neither datagram nor stream.");
    return orig_sendto(sockfd, buff, len, flags, dest, dest_len);
  }

  // Get the destination address.
  ip_addr_t dest_pliney_addr;
  result = sockaddr_to_ip(dest, dest_len, &dest_pliney_addr);

  packet_t initial_packet{};

  initial_packet.body = body_p{.len = len, .data = (uint8_t *)buff};
  initial_packet.target = dest_pliney_addr;
  initial_packet.transport = connection_type;

  auto executor = NetworkSerialPipelineExecutor{};
  auto pipeline_result = executor.execute(initial_packet, *maybe_pipeline);

  if (pipeline_result.success && pipeline_result.needs_network) {
    auto packet = *pipeline_result.packet;
    pipeline_result.socket = sockfd;

    auto netexec = InterstitialResultExecutor();
    netexec.execute(pipeline_result);

    struct sockaddr *saddr{nullptr};
    auto result = ip_to_sockaddr(packet.target, &saddr);
    if (result < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR,
          std::format(
              "Error occurred converting the pliney target to a system IP\n"));

      return orig_sendto(sockfd, buff, len, flags, dest, dest_len);
    }
    socklen_t saddr_len = result;

    auto sendto_result = orig_sendto(sockfd, packet.body.data, packet.body.len,
                                     flags, saddr, saddr_len);
    free_extensions(packet.header_extensions);
    return sendto_result;
  }
  Logger::ActiveLogger()->log(
      Logger::ERROR, std::format("Error occurred executing the pipeline: {}\n",
                                 *pipeline_result.error));

  return orig_sendto(sockfd, buff, len, flags, dest, dest_len);
}

result_pipeline_tt msghdr_to_packet(const struct msghdr *hdr) {
  packet_t packet{};

  packet.body = body_p{.len = hdr->msg_iov->iov_len,
                       .data = (uint8_t *)hdr->msg_iov->iov_base};

  if (hdr->msg_name != 0) {
    // Get the destination address.
    ip_addr_t dest_pliney_addr;
    int result = sockaddr_to_ip((const struct sockaddr *)hdr->msg_name,
                                hdr->msg_namelen, &dest_pliney_addr);
    if (result < 0) {
      return std::format("Could not convert the address in the message header "
                         "to a pliney IP address.");
    }
    packet.target = dest_pliney_addr;
  }

  return packet;
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

  if (result < 0) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, "Could not get the connection type using getsockopt.");
    return orig_sendmsg(sockfd, hdr, flags);
  }

  if (connection_type == SOCK_DGRAM) {
    connection_type = INET_DGRAM;
  } else if (connection_type == SOCK_STREAM) {
    connection_type = INET_STREAM;
  } else {
    Logger::ActiveLogger()->log(
        Logger::ERROR, "Connection type was neither datagram nor stream.");
    return orig_sendmsg(sockfd, hdr, flags);
  }

  result_pipeline_tt maybe_initial_packet{msghdr_to_packet(hdr)};

  if (std::holds_alternative<std::string>(maybe_initial_packet)) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Error occurred converting the msg (sendmsg) into a pliney "
                    "packet: {}\n",
                    std::get<std::string>(maybe_initial_packet)));
    return orig_sendmsg(sockfd, hdr, flags);
  }

  auto initial_packet = std::get<packet_t>(maybe_initial_packet);

  initial_packet.transport = connection_type;

  ip_addr_t original_target{};

  if (!hdr->msg_namelen) {
    // Because there is no name and our pipeline might need it, let's
    // fetch it ...
    struct sockaddr_storage saddr;
    socklen_t saddr_len{0};
    auto result = getsockname(sockfd, (struct sockaddr *)&saddr, &saddr_len);

    if (result < 0) {
      Logger::ActiveLogger()->log(Logger::ERROR,
                                  std::format("Error getting the sockname.\n"));
      return orig_sendmsg(sockfd, hdr, flags);
    }

    result = sockaddr_to_ip((const struct sockaddr *)&saddr, saddr_len,
                            &original_target);
    if (result < 0) {
      Logger::ActiveLogger()->log(
          Logger::ERROR, std::format("Error converting the socket.\n"));
      return orig_sendmsg(sockfd, hdr, flags);
    }

    initial_packet.target = original_target;
  }

  auto executor = NetworkSerialPipelineExecutor{};
  auto maybe_result = executor.execute(initial_packet, *maybe_pipeline);

  if (maybe_result.success && maybe_result.needs_network) {
    auto packet = *maybe_result.packet;
    maybe_result.socket = sockfd;

    auto netexec = InterstitialResultExecutor();
    netexec.execute(maybe_result);

    struct msghdr new_msghdr = netexec.get_msg();

    // If the _original_ hdr did not have an address, ours shouldn't either.
    // But, if the address changed, then we should warn the user.
    if (!hdr->msg_namelen) {
      if (original_target != packet.target) {
        Logger::ActiveLogger()->log(
            Logger::ERROR,
            std::format("Pliney modified the target of a connected socket; the "
                        "change will have no effect.\n"));
      }
      new_msghdr.msg_name = nullptr;
      new_msghdr.msg_namelen = 0;
    }

    auto sendmsg_result = orig_sendmsg(sockfd, &new_msghdr, flags);
    free_extensions(packet.header_extensions);
    return sendmsg_result;
  }
  Logger::ActiveLogger()->log(
      Logger::ERROR, std::format("Error occurred executing the pipeline: {}\n",
                                 *maybe_result.error));

  return orig_sendmsg(sockfd, hdr, flags);
}
