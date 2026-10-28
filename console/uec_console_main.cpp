

#include "uec_switch.h"
#include "uec_config.h"
#include "uec_pcap.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>

static void do_info(UecSwitch& sw, const SwitchConfig& cfg) {
  uec_cfg::print_config(cfg, "CONSOLE_INFO");
  std::printf("CONSOLE_STATE ports=%d pool_cells_used=%d\n",
              sw.n_ports, sw.pool_cells_used());
}

static void do_probe(UecSwitch& sw, const SwitchConfig& cfg, int p) {
  if (p < 0 || p >= sw.n_ports) { std::printf("CONSOLE_ERR bad port\n"); return; }
  std::printf("CONSOLE_PROBE port=%d rate=%d q0=%d q1=%d q2=%d\n",
              p, cfg.rates[p], sw.q_cells_used(p, 0), sw.q_cells_used(p, 1),
              sw.q_cells_used(p, 2));
}

static void do_stats(UecSwitch& sw, int p) {
  if (p < 0 || p >= sw.n_ports) p = 0;
  std::printf("CONSOLE_STATS port=%d fwd=%llu drop=%llu trim=%llu trim_drop=%llu "
              "pfc=%llu cbfc_cf=%llu cbfc_cc=%llu\n",
              p, (unsigned long long)sw.fwd_count[p],
              (unsigned long long)sw.drop_count[p],
              (unsigned long long)sw.trim_count(p),
              (unsigned long long)sw.trim_drop_count(p),
              (unsigned long long)sw.pfc_events(),
              (unsigned long long)sw.cf_updates(),
              (unsigned long long)sw.cc_updates());
}

static void do_queue(UecSwitch& sw, int p, int tc) {
  if (p < 0 || p >= sw.n_ports) { std::printf("CONSOLE_ERR bad port\n"); return; }
  if (tc < 0 || tc > 2) tc = 0;
  std::printf("CONSOLE_QUEUE port=%d tc=%d cells=%d\n", p, tc, sw.q_cells_used(p, tc));
}

static void do_trim(UecSwitch& sw, int p) {
  if (p < 0 || p >= sw.n_ports) { std::printf("CONSOLE_ERR bad port\n"); return; }
  std::printf("CONSOLE_TRIM port=%d trim=%llu trim_drop=%llu\n", p,
              (unsigned long long)sw.trim_count(p),
              (unsigned long long)sw.trim_drop_count(p));
}

static void do_pcap_load(UecSwitch& sw, const std::string& file, int port) {
  uec_pcap::Reader rd;
  if (!rd.open(file)) { std::printf("CONSOLE_ERR pcap open %s\n", file.c_str()); return; }
  int n = 0;
  UecFrame f;
  uint32_t sec, usec;
  while (rd.next(f, sec, usec)) {
    if (port >= 0 && port < sw.n_ports) sw.rx[port]->write(f);
    n++;
  }
  std::printf("CONSOLE_PCAP_LOAD file=%s port=%d count=%d\n", file.c_str(), port, n);
}

static void do_pcap_save(UecSwitch& sw, const std::string& file, int port) {
  uec_pcap::Writer wr;
  if (!wr.open(file)) { std::printf("CONSOLE_ERR pcap open %s\n", file.c_str()); return; }
  int n = 0;
  UecFrame f;
  if (port >= 0 && port < sw.n_ports)
    while (sw.tx[port]->nb_read(f)) { wr.write(f, 0, (uint32_t)n); n++; }
  std::printf("CONSOLE_PCAP_SAVE file=%s port=%d count=%d\n", file.c_str(), port, n);
}

int sc_main(int argc, char** argv) {
  std::string cfg_path = (argc > 1) ? argv[1] : "config/default.yaml";
  SwitchConfig cfg = uec_cfg::load_config(cfg_path);
  UecSwitch sw("sw", cfg.ports);
  uec_cfg::apply_config(sw, cfg);
  std::printf("CONSOLE_READY config=%s\n", cfg_path.c_str());

  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream is(line);
    std::string cmd;
    is >> cmd;
    if (cmd.empty()) continue;
    if (cmd == "info") {
      do_info(sw, cfg);
    } else if (cmd == "probe") {
      int p = 0; is >> p; do_probe(sw, cfg, p);
    } else if (cmd == "stats") {
      int p = 0; if (!(is >> p)) p = 0; do_stats(sw, p);
    } else if (cmd == "queue") {
      int p = 0, tc = 0; is >> p >> tc; do_queue(sw, p, tc);
    } else if (cmd == "trim") {
      int p = 0; is >> p; do_trim(sw, p);
    } else if (cmd == "pcap") {
      std::string sub, file; int p = 0;
      is >> sub >> file >> p;
      if (sub == "load") do_pcap_load(sw, file, p);
      else if (sub == "save") do_pcap_save(sw, file, p);
      else std::printf("CONSOLE_ERR pcap subcommand\n");
    } else if (cmd == "run") {
      int ns = 1000; is >> ns; sc_start(ns, SC_NS);
      std::printf("CONSOLE_RUN ns=%d now=%s\n", ns, sc_time_stamp().to_string().c_str());
    } else if (cmd == "quit" || cmd == "exit") {
      break;
    } else {
      std::printf("CONSOLE_ERR unknown %s\n", cmd.c_str());
    }
  }
  std::printf("CONSOLE_DONE\n");
  sc_stop();
  return 0;
}
