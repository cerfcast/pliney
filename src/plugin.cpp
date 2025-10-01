#include "packetline/plugin.hpp"
#include "api/plugin.h"
#include "packetline//logger.hpp"

#include <algorithm>
#include <dlfcn.h>
#include <iostream>
#include <regex>

bool Plugin::load() {
  void *loaded = dlopen(m_path.c_str(), RTLD_NOW);

  if (!loaded) {
    std::cout << std::format("Could not load the plugin library: {}\n",
                             dlerror());
    return false;
  }

  load_t load_function = (load_t)dlsym(loaded, "load");

  if (!load_function) {
    std::cout << std::format(
        "Could not find the load function for library: {}\n", m_path.c_str());
    return false;
  }

  std::cout << std::format("Load of plugin at path {} was successful!\n",
                           m_path.c_str());

  auto load_result = load_function(&info);

  if (load_result) {
    m_name = info.name;
  }

  return load_result;
}

plugin_cleanup_result_tt Plugin::cleanup(void *cookie) {
  if (info.cleanup == nullptr) {
    Logger::ActiveLogger()->log(
        Logger::ERROR,
        std::format("Plugin {} specified no cleanup actions.", info.name));
    return {};
  }

  auto cleanup_result = info.cleanup(cookie);

  if (cleanup_result.success) {
    return {};
  }

  return cleanup_result.errstr;
}

result_generate_result_tt Plugin::generate(packet_t *packet,
                                           void *cookie) const {
  if (info.generator) {

    auto result = info.generator(packet, cookie);

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
  auto plugin_matcher = std::regex{"libpliney_pl_.*.so"};
  auto loaded_plugins = std::vector<Plugin>{};

  std::ranges::for_each(dir, [&](auto v) {
    if (std::regex_match(v.path().filename().c_str(), plugin_matcher)) {
      std::cout << std::format("Attempting to load plugin at {} ...\n",
                               v.path().filename().c_str());
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
