#ifndef IPC_CMD_H
#define IPC_CMD_H

#include <string>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "libbpf_print.h"
#include "model/tracker.h"
#include "prometheus_server.h"

extern "C" {
#include <ipc/ipc_tracker.h>
}

/// ebpf LSM ipc tracker
struct ipc_tracker : public tracker_with_config<ipc_env, ipc_event> {

  ipc_tracker(config_data config);

  // create a tracker with deafult config
  static std::unique_ptr<ipc_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<ipc_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  void start_tracker();

  // convert event to json
  struct json_event_handler : public event_handler<ipc_event>
  {
    std::string to_json(const struct ipc_event &e);
  };

  // used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler
  {
    void handle(tracker_event<ipc_event> &e);
  };

  struct plain_text_event_printer : public event_handler<ipc_event>
  {
    void handle(tracker_event<ipc_event> &e);
  };

  struct csv_event_printer : public event_handler<ipc_event>
  {
  public:
    csv_event_printer() {
      std::filesystem::create_directories("agent_data");
      auto now = std::chrono::system_clock::now();
      auto now_c = std::chrono::system_clock::to_time_t(now);
      std::stringstream ss;
      ss << "agent_data/ipc_"
         << std::put_time(std::localtime(&now_c), "%Y%m%d_%H%M%S") << ".csv";
      filename = ss.str();
      
      file.open(filename);
      if (file.is_open()) {
        file << "timestamp,pid,uid,gid,cuid,cgid\n";
        file.flush();
      }
    }

    ~csv_event_printer() {
      if (file.is_open()) {
        file.close();
        spdlog::info("IPC CSV data saved to: {}", filename);
      }
    }

    void handle(tracker_event<ipc_event> &e) override {
      if (!file.is_open()) return;
      
      std::string row = fmt::format("{},{},{},{},{},{}",
          get_current_time(),
          e.data.pid,
          e.data.uid,
          e.data.gid,
          e.data.cuid,
          e.data.cgid);
      
      file << row << "\n";
      file.flush();
    }

  private:
    std::ofstream file;
    std::string filename;
  };
};

#endif
