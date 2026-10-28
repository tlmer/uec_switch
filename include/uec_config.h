

#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include "uec_switch.h"

struct SwitchConfig {
  int ports = 2;
  std::vector<int> rates;
  int cell_bytes = 256;
  int pool_cells = 32768;
  int q_limit = 64;
  int ecn_min = 16, ecn_max = 32;
  int trim_th = 48, drop_th = 57, min_trim = 24;
  bool ecn = true, trim = true, csig = false, ufh = true;
  bool cbfc = false, pfc = false;
  uint8_t dscp_trimmable = 10, dscp_trimmed = 12;
  int cbfc_vcs = 32, cbfc_window = 32;
  int pfc_xoff = 16, pfc_xon = 8, pfc_quanta = 1000;
};

namespace uec_cfg {

struct Yaml {
  std::map<std::string, std::string> kv;

  static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
  }
  static std::string strip_comment(const std::string& s) {
    bool inq = false;
    for (size_t i = 0; i < s.size(); i++) {
      if (s[i] == '"') inq = !inq;
      if (s[i] == '#' && !inq) return s.substr(0, i);
    }
    return s;
  }
  static bool parse_file(const std::string& path, Yaml& y) {
    FILE* fp = std::fopen(path.c_str(), "r");
    if (!fp) return false;
    std::vector<std::pair<int, std::string>> stack;
    char line[4096];
    while (std::fgets(line, sizeof(line), fp)) {
      std::string raw = strip_comment(line);
      raw = trim(raw);
      if (raw.empty()) continue;
      int ind = 0;
      while (line[ind] == ' ') ind++;
      size_t colon = raw.find(':');
      if (colon == std::string::npos) continue;
      std::string key = trim(raw.substr(0, colon));
      std::string val = trim(raw.substr(colon + 1));
      while (!stack.empty() && stack.back().first >= ind) stack.pop_back();
      std::string path_key;
      for (auto& p : stack) path_key += p.second + ".";
      path_key += key;
      if (val.empty()) {
        stack.push_back({ind, key});
      } else {
        if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
          val = val.substr(1, val.size() - 2);
        y.kv[path_key] = val;
      }
    }
    std::fclose(fp);
    return true;
  }
  bool has(const std::string& k) const { return kv.find(k) != kv.end(); }
  std::string str(const std::string& k, const std::string& d = "") const {
    auto it = kv.find(k);
    return it == kv.end() ? d : it->second;
  }
  int integer(const std::string& k, int d) const {
    auto it = kv.find(k);
    if (it == kv.end()) return d;
    return std::atoi(it->second.c_str());
  }
  double real(const std::string& k, double d) const {
    auto it = kv.find(k);
    if (it == kv.end()) return d;
    return std::atof(it->second.c_str());
  }
  bool boolean(const std::string& k, bool d) const {
    auto it = kv.find(k);
    if (it == kv.end()) return d;
    std::string s = it->second;
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (s == "true" || s == "1" || s == "yes" || s == "on" || s == "enabled")
      return true;
    if (s == "false" || s == "0" || s == "no" || s == "off" ||
        s == "disabled" || s == "none")
      return false;
    return !s.empty();                      
  }
  std::vector<int> int_list(const std::string& k) const {
    std::vector<int> out;
    auto it = kv.find(k);
    if (it == kv.end()) return out;
    std::string s = it->second;
    for (char& c : s) if (c == '[' || c == ']' || c == ',') c = ' ';
    std::istringstream is(s);
    std::string tok;
    while (is >> tok) out.push_back(std::atoi(tok.c_str()));
    return out;
  }
};

inline SwitchConfig load_config(const std::string& path) {
  SwitchConfig c;
  Yaml y;
  if (!Yaml::parse_file(path, y)) return c;

  
  c.ports = y.integer("ports.count", y.integer("switch.ports", c.ports));
  std::vector<int> rates = y.int_list("ports.rates");
  if (rates.empty()) rates = y.int_list("switch.rates");
  if (!rates.empty()) c.rates = rates;
  if ((int)c.rates.size() < c.ports) c.rates.resize(c.ports, 200);

  c.cell_bytes = y.integer("buffer.cell_bytes", c.cell_bytes);
  int pool_bytes = y.integer("buffer.pool_bytes", c.pool_cells * c.cell_bytes);
  c.pool_cells = pool_bytes / (c.cell_bytes > 0 ? c.cell_bytes : 256);

  
  c.q_limit = y.integer("qos.q_limit", y.integer("buffer.q_limit", c.q_limit));
  if (y.has("qos.ecn_min")) {
    c.ecn_min = y.integer("qos.ecn_min", c.ecn_min);
    c.ecn_max = y.integer("qos.ecn_max", c.ecn_max);
    c.trim_th = y.integer("qos.trim_th", c.trim_th);
    c.drop_th = y.integer("qos.drop_th", c.drop_th);
  } else if (y.has("buffer.thresholds_frac.ecn_min")) {
    c.ecn_min = (int)(y.real("buffer.thresholds_frac.ecn_min", 0.25) * c.q_limit);
    c.ecn_max = (int)(y.real("buffer.thresholds_frac.ecn_max", 0.50) * c.q_limit);
    c.trim_th = (int)(y.real("buffer.thresholds_frac.trim", 0.75) * c.q_limit);
    c.drop_th = (int)(y.real("buffer.thresholds_frac.drop", 0.90) * c.q_limit);
  }
  c.min_trim = y.integer("trim.min_trim_size_bytes", c.min_trim);
  c.trim = y.boolean("trim.enabled", c.trim);
  c.ecn = y.boolean("ecn.enabled", c.ecn);
  c.csig = y.boolean("features.csig", c.csig);
  c.ufh = y.boolean("features.ufh", c.ufh);
  c.cbfc = y.boolean("features.cbfc", c.cbfc);
  c.pfc = y.boolean("features.pfc", c.pfc);
  
  
  auto int_opt = [&](const std::string& k, int d) {
    auto it = y.kv.find(k);
    if (it == y.kv.end() || it->second.empty()) return d;
    const std::string& s = it->second;
    if (!(std::isdigit((unsigned char)s[0]) || s[0] == '-')) return d;
    return std::atoi(s.c_str());
  };
  c.dscp_trimmable = (uint8_t)int_opt("trim.dscp_trimmable", c.dscp_trimmable);
  c.dscp_trimmed = (uint8_t)int_opt("trim.dscp_trimmed", c.dscp_trimmed);
  c.cbfc_vcs = y.integer("cbfc.num_vc", c.cbfc_vcs);
  c.cbfc_window = y.integer("cbfc.window", c.cbfc_window);
  c.pfc_xoff = y.integer("pfc.xoff", c.pfc_xoff);
  c.pfc_xon = y.integer("pfc.xon", c.pfc_xon);
  c.pfc_quanta = y.integer("pfc.quanta", c.pfc_quanta);
  return c;
}

inline void apply_config(UecSwitch& sw, const SwitchConfig& c) {
  for (int p = 0; p < c.ports && p < (int)c.rates.size(); p++)
    sw.set_port_rate(p, c.rates[p]);
  sw.set_qos(c.q_limit, c.ecn_min, c.ecn_max, c.trim_th, c.drop_th, c.min_trim);
  sw.set_features_ex(c.ecn, c.trim, c.csig, c.ufh, c.cbfc, c.pfc);
  sw.set_trim_codepoints(c.dscp_trimmable, c.dscp_trimmed);
  sw.set_pfc_thresholds(c.pfc_xoff, c.pfc_xon, c.pfc_quanta);
}

inline void print_config(const SwitchConfig& c, const char* tag = "CONSOLE_INFO") {
  std::printf("%s ports=%d rates=", tag, c.ports);
  for (int r : c.rates) std::printf("%d,", r);
  std::printf(" cell=%d pool_cells=%d q_limit=%d ecn=%d/%d trim_th=%d drop_th=%d "
              "min_trim=%d ecn_en=%d trim_en=%d csig=%d ufh=%d cbfc=%d pfc=%d "
              "dscp_tri=%u dscp_trimmed=%u\n",
              c.cell_bytes, c.pool_cells, c.q_limit, c.ecn_min, c.ecn_max,
              c.trim_th, c.drop_th, c.min_trim, c.ecn ? 1 : 0, c.trim ? 1 : 0,
              c.csig ? 1 : 0, c.ufh ? 1 : 0, c.cbfc ? 1 : 0, c.pfc ? 1 : 0,
              (unsigned)c.dscp_trimmable, (unsigned)c.dscp_trimmed);
}

}  
