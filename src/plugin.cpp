#include "packetline/plugin.hpp"
#include "api/plugin.h"

#include <algorithm>
#include <dlfcn.h>
#include <iostream>
#include <regex>

bool Plugin::load() {
  void *loaded = dlopen(m_path.c_str(), RTLD_NOW);

  if (loaded) {
    load_t load_function = (load_t)dlsym(loaded, "load");

    name_t name_function = (name_t)dlsym(loaded, "name");
    m_name = name_function();

    m_generator = (generate_t)dlsym(loaded, "generate");

    m_generate_configurationer =
        (generate_configuration_t)dlsym(loaded, "generate_configuration");

    std::cout << std::format("Load of '{}' plugin was successful!\n", m_name);
    return load_function();
  }
  std::cout << std::format("Could not load the plugin library: {}\n",
                           dlerror());
  return false;
}

maybe_generate_result_t Plugin::generate(ip_addr_t source_ip,
                                         ip_addr_t destination_ip,
                                         extensions_p extensions, body_p body,
                                         void *cookie) const {
  if (m_generator) {

    auto result = m_generator(source_ip, destination_ip, extensions, body, cookie);

    if (result.success) {
      return result;
    }
    return "Error invoking plugin";
  }
  return "No generator available";
}

std::optional<Plugin>
Plugins::plugin_by_name(const std::string_view &plugin_name) {
  auto result = std::find_if(
      m_plugins.begin(), m_plugins.end(),
      [&plugin_name](auto plugin) { return plugin.name() == plugin_name; });
  if (result != m_plugins.end()) {
    return *result;
  }
  return {};
}

std::vector<Plugin> PluginDir::plugins() {
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
