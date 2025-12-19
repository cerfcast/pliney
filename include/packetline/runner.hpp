#ifndef _RESULT_EXECUTORS_HPP
#define _RESULT_EXECUTORS_HPP

#include <cstring>
#include <string_view>
#include <sys/socket.h>

#include "packetline/utilities.hpp"
#include "pisa/compilation.hpp"
#include "pisa/pisa.h"

class Runner {
public:
  using RunnerConfigureResult = std::variant<size_t, std::string>;

  virtual bool execute(Compilation &compilation) = 0;
  virtual RunnerConfigureResult configure(const std::vector<std::string> &args) {
    return size_t{0};
  };
  virtual ~Runner() = default;

protected:
  bool find_program_target_transport(const unique_pisa_program_t &program,
                                     ip_addr_t &pisa_target_address,
                                     Pliney::Transport &transport);
};

class PacketRunner : public Runner {
public:
  bool execute(Compilation &compilation) override;
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
  RunnerConfigureResult configure(const std::vector<std::string> &args) override;
private:
  std::string m_aped_iface_name;
  std::string m_ip_iface_name;
};

class TestSenderRunner : public Runner {
public:
  bool execute(Compilation &compilation) override {
    return true;
  };
  RunnerConfigureResult configure(const std::vector<std::string> &args) override;
};

#endif
