#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
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

#include "packetline.h"
#include "plugin.h"
#include "utils.h"

#include <unistd.h>

#include <errno.h>

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

  std::string name() { return m_name; }

  maybe_generate_result_t generate(ip_addr_t source_ip, ip_addr_t destination_ip, body_p body) {
    if (m_generator) {

      auto result = m_generator(source_ip, destination_ip, body);

      auto target_addr = stringify_ip(result.destination);

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
          std::cout << std::format("Successfully loaded --{}-- plugin.\n",
                                   p.name());
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
  virtual maybe_generate_result_t execute(std::vector<Plugin> plugins) = 0;
};

class SerialPipelineExecutor : public PipelineExecutor {
public:
  maybe_generate_result_t execute(std::vector<Plugin> plugins) override {

    ip_addr_t target_ip{};
    ip_addr_t source_ip{};
    body_p body{};

    for (auto plugin : plugins) {

      auto result = plugin.generate(source_ip, target_ip, body);

      if (std::holds_alternative<generate_result_t>(result)) {
        std::cout << "Got a result!\n";
        generate_result_t x = std::get<generate_result_t>(result);
        target_ip = x.destination;
        body = x.body;
      } else {
        std::cout << std::format("There was an error: {}\n",
                                 std::get<std::string>(result));
        return std::get<std::string>(result);
      }
    }

    return generate_result_t{target_ip, source_ip, body};
  }
};

int main() {
  auto plugin_path = std::filesystem::path("./build");
  auto plugins = PluginDir{plugin_path};
  auto loaded_plugins = plugins.plugins();

  if (loaded_plugins.empty()) {
    std::cerr << "No plugins loaded.\n";
    return 1;
  }

  auto executor = SerialPipelineExecutor{};
  auto maybe_result = executor.execute(loaded_plugins);

  if (std::holds_alternative<generate_result_t>(maybe_result)) {

    auto actual_result = std::get<generate_result_t>(maybe_result);
    auto skt = ip_to_socket(actual_result.destination);

    if (skt < 0) {
      std::cerr << std::format("Error occurred sending data: could not open the socket: \n", strerror(errno));
      return -1;
    }

    struct sockaddr *destination = nullptr;
    int destination_len = ip_to_sockaddr(actual_result.destination, &destination);
    if (destination_len < 0) {
      std::cerr << "Error occurred converting generated destination into system-compatible destination.\n";
      close(skt);
      return -1;
    }

    auto connect_result = connect(skt, destination, destination_len);
    if (connect_result < 0) {
      std::cerr << std::format("Error occurred sending data: could not connect the socket: \n", strerror(errno));
      close(skt);
      return -1;
    }

    int write_result = write(skt, actual_result.body.data, actual_result.body.len);

    if (write_result < 0) {
      std::cerr << std::format("Error occurred sending data: could not write to the socket: \n", strerror(errno));
      close(skt);
      return -1;
    }

    close(skt);

    return 0;
  }

  std::cerr << std::format("An error occurred processing the packet pipeline: {}\n", std::get<std::string>(maybe_result));

  return 1;
}