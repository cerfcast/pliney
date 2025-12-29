#ifndef _RESULT_EXECUTORS_HPP
#define _RESULT_EXECUTORS_HPP

#include <cstddef>
#include <cstring>
#include <sys/socket.h>

#include "packetline/constants.hpp"
#include "packetline/utilities.hpp"
#include "pisa/compilation.hpp"
#include "pisa/pisa.h"

struct IpRunnerPacket {
  Pliney::IpVersion version;
  size_t len;
  union {
    struct iphdr *ip;
    struct ip6_hdr *ip6;
  } hdr;
};

struct RunnerPacketOpts {
  size_t ip_opt_ext_hdr_raw_len{0};
  uint8_t *ip_opts_exts_hdr_raw{nullptr};
  pisa_ip_opts_exts_t ip_opts_exts_hdr{};
};

struct TransportRunnerPacket {
  size_t transport_len{0};
  void *transport{nullptr};
  size_t transportoptionhdr_len{0};
  uint8_t *transportoptionhdr{nullptr};
};

struct RunnerPacketBody {
  size_t len{0};
  void *body{nullptr};
};

struct RunnerPacket {
  IpRunnerPacket ip_packet;
  RunnerPacketOpts opts;
  TransportRunnerPacket transport_packet;
  RunnerPacketBody body;

  static std::variant<RunnerPacket, std::string>
  from(const unique_pisa_program_t &pisa_program);
  static std::variant<RunnerPacket, std::string> from(const pisa_ptr_value_t data);
};

class Runner {
public:
  using RunnerConfigureResult = std::variant<size_t, std::string>;

  virtual bool execute(Compilation &compilation) = 0;
  virtual RunnerConfigureResult
  configure(const std::vector<std::string> &args) {
    return size_t{0};
  };
  virtual ~Runner() = default;

  static bool
  find_program_target_transport(const unique_pisa_program_t &program,
                                ip_addr_t &pisa_target_address,
                                Pliney::Transport &transport);
};

class PacketRunner : public Runner {
public:
  bool execute(Compilation &compilation) override;
  static bool execute(Compilation &compilation, RunnerPacket packet);
};

class PacketSenderRunner : public PacketRunner {
public:
  bool execute(Compilation &) override;
};

class SocketBuilderRunner : public Runner {
public:
  bool execute(Compilation &compilation) override;

private:
  bool execute_set_field(Compilation &compilation, pisa_inst_t instruction,
                         pisa_value_t &pisa_pgm_body,
                         std::optional<ip_addr_t> &maybe_pgm_source,
                         ip_addr_t pliney_destination);

protected:
  int m_socket;
  std::optional<Swapsockopt<int>> m_ttlhl{};
  std::optional<Swapsockopt<int>> m_toss{};
  std::optional<std::unique_ptr<struct sockaddr, SockaddrDeleter>>
      m_destination;
  size_t m_destination_len{};
  pisa_ip_opts_exts_t m_ip_opts_exts_hdr{.opts_exts_count = 0,
                                         .opt_ext_values = nullptr};
};

class CliRunner : public SocketBuilderRunner {
public:
  bool execute(Compilation &compilation) override;
};

class ForkRunner : public SocketBuilderRunner {
  using pisa_callback_t = void (*)(int, void *);

public:
  bool execute(Compilation &compilation) override;
};

class XdpRunner : public Runner {
public:
  bool execute(Compilation &compilation) override;
  RunnerConfigureResult
  configure(const std::vector<std::string> &args) override;

private:
  std::string m_aped_iface_name;
  std::string m_ip_iface_name;
};

class TestSenderRunner : public Runner {
public:
  bool execute(Compilation &compilation) override { return true; };
  RunnerConfigureResult
  configure(const std::vector<std::string> &args) override;
};

#endif
