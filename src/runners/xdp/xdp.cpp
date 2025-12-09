#include "lib/logger.hpp"
#include "packetline/runner.hpp"

#include "pisa/compilation.hpp"

#include <packetline/runners/xdp/xdpsock.h>

#include <cstring>
#include <signal.h>


static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];
int sock;

static bool keep_running{true};

static void int_exit(int sig) { keep_running = false; }

void packet_processor(void *pkt) {
  char *cpkt{static_cast<char *>(pkt)};
  struct ether_header *eth{reinterpret_cast<struct ether_header*>(cpkt)};

  struct iphdr *iph{reinterpret_cast<struct iphdr*>(cpkt + sizeof(struct ether_header))};

  iph->ttl = 22;
  iph->check = 0;
  iph->check = ip_fast_csum(iph, iph->ihl);

}

void l2fwd_all(int tunfd) {

  if (tunfd < 0) {
    printf("Error allocating tun interface!\n");
    return;
  }

  for (;;) {
    for (int i = 0; i < num_socks; i++)
      l2fwd(xsks[i], tunfd, packet_processor);

    // Fix: Need a way to stop.
    if (!keep_running) {
      Logger::ActiveLogger()->log(Logger::DEBUG, "Stopping xdp.");
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

  auto opt_ifindex = if_nametoindex(m_interface_name.c_str());
  if (!opt_ifindex) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Cannot use interface {} for XDP runner: it does not exist", m_interface_name));
    return false;
  }

  load_xdp_program(opt_ifindex);

  bufs = mmap(NULL, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE,
              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (bufs == MAP_FAILED) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("There was an error performing mmap: {}", strerror(errno)));
    return false;
  }

  umem = xsk_configure_umem(bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
  xsk_populate_fill_ring(umem);
  for (i = 0; i < 1; i++)
    xsks[num_socks++] =
        xsk_configure_socket(umem, m_interface_name.c_str(), true, true);

  for (i = 0; i < 1; i++)
    apply_setsockopt(xsks[i]);

  enter_xsks_into_map(xsks, 1);

  signal(SIGINT, int_exit);
  signal(SIGTERM, int_exit);
  signal(SIGABRT, int_exit);

  setlocale(LC_ALL, "");

  char dev_name[IFNAMSIZ] = "tapst0";
  int tunfd = tun_alloc_aper(dev_name, m_interface_name.c_str());

  l2fwd_all(tunfd);

out:

  xdpsock_cleanup(xsks, 1);
  remove_xdp_program(opt_ifindex);

  munmap(bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);

  return true;
}

Runner::RunnerConfigureResult XdpRunner::configure(const std::vector<std::string> &args) {

  std::string usage{"xdp requires -iface [NAME]"};
  if (args.size() < 2) {
    return usage;
  }

  if (args[0] != "-iface") {
    return usage;
  }

  m_interface_name = args[1];

  return size_t(2);

}