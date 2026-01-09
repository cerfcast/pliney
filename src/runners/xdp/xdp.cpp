#include "lib/ip.hpp"
#include "lib/logger.hpp"
#include "packetline/constants.hpp"
#include "packetline/runner.hpp"

#include "pisa/compilation.hpp"
#include "pisa/pisa.h"

#include <cstdint>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <packetline/runners/xdp/faux.h>
#include <packetline/runners/xdp/xdpsupport.h>

#include <cstring>
#include <format>
#include <pthread.h>
#include <signal.h>

static bool keep_running{true};

static void xdp_runner_execute_interrupt(int sig) { keep_running = false; }

bool XdpRunner::execute(Compilation &compilation) {

  if (!compilation) {
    return false;
  }

  struct xsk_umem_info *umem;
  void *bufs;
  pthread_t tap_handler_pt;
  faux_process_transport_egress_config_t egress_config;

  // Before doing anything that might need to be cleaned up, let's check some
  // things.

  auto transport_iface_idx = if_nametoindex(m_aped_iface_name.c_str());
  if (!transport_iface_idx) {
    Logger::ActiveLogger().log(
        Logger::ERROR, std::format("Cannot ape interface {}: it does not exist",
                                   m_aped_iface_name));
    return false;
  }
  int transport_fd =
      faux_alloc_transport(m_aped_iface_name.c_str(), transport_iface_idx);

  int ip_fd = faux_alloc_ip(m_ip_iface_name.c_str(), m_aped_iface_name.c_str());
  auto ip_iface_idx = if_nametoindex(m_ip_iface_name.c_str());
  if (!ip_iface_idx) {
    Logger::ActiveLogger().log(
        Logger::ERROR,
        std::format("Cannot use {} as the IP interface: it does not exist",
                    m_ip_iface_name));
    return false;
  }

  // General XDP setup.
  bufs = mmap(NULL, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE,
              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (bufs == MAP_FAILED) {
    Logger::ActiveLogger().log(
        Logger::ERROR, std::format("There was an error performing mmap when "
                                   "allocating XDP buffers: {}",
                                   strerror(errno)));
    return false;
  }

  umem =
      xdp_xsk_configure_umem(bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
  xsk_populate_fill_ring(umem);

  struct xsk_socket_info *xsk{
      xdp_xsk_configure_socket(umem, m_aped_iface_name.c_str(), true, true)};
  xdp_apply_setsockopt(xsk);

  // Prepare a way to quit.
  signal(SIGINT, xdp_runner_execute_interrupt);
  signal(SIGTERM, xdp_runner_execute_interrupt);
  signal(SIGABRT, xdp_runner_execute_interrupt);

  egress_config.ip_fd = ip_fd;
  egress_config.transport_fd = transport_fd;
  egress_config.transport_iface_idx = transport_iface_idx;
  egress_config.keep_going = &keep_running;
  auto processor = [&compilation](void *raw, size_t len, size_t *new_len) {
    struct ether_header *eth{reinterpret_cast<struct ether_header *>(raw)};

    // Processor setup guarantees that we will only see IP-wrapped-in-ethernet
    // packets.

    // Generate a RunnerPacket from the raw data, if possible.
    auto rp{RunnerPacket::from(
        pisa_ptr_value_t{.data = (uint8_t *)raw, .len = len})};

    // If there was an error parsing, ...
    if (std::holds_alternative<std::string>(rp)) {
      // TODO: Determine how to better handle an error. Just log it for now.
      Logger::ActiveLogger().log(Logger::ERROR,
                                 std::format("Error processing packet: {}.",
                                             std::get<std::string>(rp)));
      *new_len = len;
      return raw;
    } else {
      Logger::ActiveLogger().log(Logger::DEBUG,
                                 std::format("Processing a packet!"));
      auto actual_rp{std::get<RunnerPacket>(rp)};
      auto result = PacketRunner::execute(compilation, actual_rp);

      char *new_packet{(char *)malloc(sizeof(struct ether_header) +
                                      compilation.packet.all.len)};

      memcpy(new_packet, raw, sizeof(struct ether_header));
      memcpy(new_packet + sizeof(struct ether_header),
             compilation.packet.all.data, compilation.packet.all.len);

      *new_len = compilation.packet.all.len + sizeof(struct ether_header);
      return (void *)new_packet;
    }
  };
  egress_config.packet_processor = processor;
  int tap_handler_create_result =
      pthread_create(&tap_handler_pt, nullptr, faux_process_transport_egress,
                     (void *)&egress_config);

  Logger::ActiveLogger().log(Logger::DEBUG, "Starting xdp ingress processing.");
  for (;;) {
    faux_process_transport_ingress(xsk, ip_fd, processor);

    if (!keep_running) {
      break;
    }
  }
  Logger::ActiveLogger().log(Logger::DEBUG, "Stopping xdp ingress processing.");

  xdp_cleanup_sock(xsk);

  munmap(bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);

  return true;
}

Runner::RunnerConfigureResult
XdpRunner::configure(const std::vector<std::string> &args) {

  std::string usage{"xdp requires -apediface [NAME] -ipiface [NAME]"};
  if (args.size() < 4) {
    return usage;
  }

  if (args[0] != "-apediface") {
    return usage;
  }
  m_aped_iface_name = args[1];

  if (args[2] != "-ipiface") {
    return usage;
  }
  m_ip_iface_name = args[3];

  return size_t(4);
}