#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <dlfcn.h>
#include <filesystem>
#include <format>
#include <iostream>
#include <netinet/in.h>
#include <regex>
#include <sys/socket.h>
#include <variant>
#include <vector>

#include "dlfcn.h"

#include "plugin.h"
#include "packetline.h"

std::string stringify_ip(ip_addr_t addr) {
  if (addr.type == INET_ADDR_V4) {
    struct in_addr to_convert{};
    char buff[128];

    to_convert.s_addr = addr.addr.ipv4.s_addr;
    auto stringed = inet_ntop(AF_INET, &to_convert, buff, 128);

    return std::string{stringed};

  } else if (addr.type == INET_ADDR_V6) {
  }
  return "";
}

class Plugin {
public:
  explicit Plugin(std::filesystem::path path) : m_path(path) {}

  bool load() {
    void *loaded = dlopen(m_path.c_str(), RTLD_NOW);

    if (loaded) {
      load_t load_function = (load_t)dlsym(loaded, "load");

      name_t name_function = (name_t)dlsym(loaded, "name");
      m_name = name_function();

      m_generator = (generate_t)dlsym(loaded, "generate");

      std::cout << std::format("Load of --{}-- plugin was successful!\n",
                               m_name);
      return load_function();
    }
    std::cout << std::format("Could not load the plugin library: {}\n",
                             dlerror());
    return false;
  }

  std::string name() {
    return m_name;
  }

  maybe_generate_result_t generate() {
    if (m_generator) {

      auto result = m_generator(ip_addr_t{}, body_p{});

      auto target_addr = stringify_ip(result.address);

      std::cout << std::format("Target address: {}\n", target_addr);
      return result;
    }
    return "No generator available";
  }

private:
  std::filesystem::path m_path;
  std::string m_name;
  generate_t m_generator{nullptr};
};

class PluginDir {
public:
  explicit PluginDir(std::filesystem::path p) : m_path(p) {}

  std::vector<Plugin> plugins() {
    auto dir = std::filesystem::directory_iterator{m_path};
    auto plugin_matcher = std::regex{"lib.*.so"};
    auto loaded_plugins = std::vector<Plugin>{};

    std::ranges::for_each(dir, [&](auto v) {
      if (std::regex_match(v.path().filename().generic_string(),
                           plugin_matcher)) {
        std::cout << std::format("Attempting to load plugin at {} ...\n",
                                 v.path().filename().generic_string());
        Plugin p{v};

        if (p.load()) {
          std::cout << std::format("Successfully loaded --{}-- plugin.\n", p.name());
          loaded_plugins.push_back(p);
        } else {
          std::cerr << "Load failed!\n";
        };
      }
    });

    return loaded_plugins;
  };

private:
  std::filesystem::path m_path;
};

class PipelineExecutor {
public:
  void virtual execute(std::vector<Plugin> plugins) = 0;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  void execute(std::vector<Plugin> plugins) {
    std::ranges::for_each(plugins, [](auto p) {
      auto result = p.generate();

      if (std::holds_alternative<generate_result_t>(result)) {
        std::cout << "Got a result!\n";
      } else {
        std::cout << std::format("There was an error: {}\n",
                                 std::get<std::string>(result));
      }
    });
  }
};

int main() {
  auto plugin_path = std::filesystem::path("./build");

  auto plugins = PluginDir{plugin_path};

  auto executor = SerialPipelineExecutor{};

  auto loaded_plugins = plugins.plugins();
  executor.execute(loaded_plugins);
}