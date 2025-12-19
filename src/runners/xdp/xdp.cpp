#include "lib/logger.hpp"
#include "packetline/runner.hpp"

#include "pisa/compilation.hpp"

#include <cstddef>
#include <net/if.h>
#include <packetline/runners/xdp/xdpsock.h>

#include <cstring>
#include <pthread.h>
#include <signal.h>

static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];
int sock;

static bool keep_running{true};

static void int_exit(int sig) { keep_running = false; }

void packet_processor(void *pkt) {
  char *cpkt{static_cast<char *>(pkt)};
  struct ether_header *eth{reinterpret_cast<struct ether_header *>(cpkt)};

  struct iphdr *iph{
      reinterpret_cast<struct iphdr *>(cpkt + sizeof(struct ether_header))};

  iph->ttl = 22;
  iph->check = 0;
  iph->check = ip_fast_csum((const unsigned char *)iph, iph->ihl);
}

void xdp_process_ingress(int tapfd) {
  for (;;) {
    for (int i = 0; i < num_socks; i++)
      xdp_process_ingress(xsks[i], tapfd, packet_processor);

    // Fix: Need a way to stop.
    if (!keep_running) {
      Logger::ActiveLogger()->log(Logger::DEBUG,
                                  "Stopping xdp ingress processing.");
      break;
    }
  }
}

bool XdpRunner::execute(Compilation &compilation) {

  if (!compilation) {
    return false;
  }

  struct xsk_umem_info *umem;
  int xsks_map_fd = 0;
  int i, ret;
  void *bufs;

  auto opt_ifindex = if_nametoindex(m_aped_iface_name.c_str());
  if (!opt_ifindex) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, std::format("Cannot ape interface {}: it does not exist",
                                   m_aped_iface_name));
    return false;
  }

  bufs = mmap(NULL, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE,
              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (bufs == MAP_FAILED) {
    Logger::ActiveLogger()->log(
        Logger::ERROR, std::format("There was an error performing mmap when "
                                   "allocating XDP buffers: {}",
                                   strerror(errno)));
    return false;
  }

  umem =
      xdp_xsk_configure_umem(bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
  xsk_populate_fill_ring(umem);
  for (i = 0; i < 1; i++)
    xsks[num_socks++] =
        xdp_xsk_configure_socket(umem, m_aped_iface_name.c_str(), true, true);

  for (i = 0; i < 1; i++)
    xdp_apply_setsockopt(xsks[i]);

  signal(SIGINT, int_exit);
  signal(SIGTERM, int_exit);
  signal(SIGABRT, int_exit);

  int tunfd =
      tun_alloc_aper(m_ip_iface_name.c_str(), m_aped_iface_name.c_str());
  int rawi = if_nametoindex(m_aped_iface_name.c_str());
  int rawfd = raw_alloc_aper(m_aped_iface_name.c_str());

  pthread_t tap_handler_pt;

  tap_process_egress_config_t egress_config;

  egress_config.tunfd = tunfd;
  egress_config.rawfd = rawfd;
  egress_config.rawi = rawi;
  egress_config.keep_going = &keep_running;
  egress_config.packet_processor = packet_processor;

  int tap_handler_create_result = pthread_create(
      &tap_handler_pt, nullptr, tap_process_egress, (void *)&egress_config);

  xdp_process_ingress(tunfd);

  xdp_cleanup(xsks, 1);

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