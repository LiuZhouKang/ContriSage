#ifndef SYSCALL_CMD_H
#define SYSCALL_CMD_H

#include <mutex>
#include <thread>
#include <string>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "libbpf_print.h"
#include "model/tracker.h"
#include "prometheus/counter.h"
#include "prometheus_server.h"

extern "C" {
#include <syscall/syscall_tracker.h>
#include "syscall_helper.h"
}

/// syscall tracker cpp interface

/// catch all syscall enter and exit events
class syscall_tracker : public tracker_with_config<syscall_env, syscall_event> {
public:
  syscall_tracker(config_data config);

  // create a tracker with deafult config
  static std::unique_ptr<syscall_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<syscall_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  void start_tracker();

  // used for prometheus exporter
  struct prometheus_event_handler : public event_handler<syscall_event>
  {
    // read times counter for field reads
    prometheus::Family<prometheus::Counter> &agent_files_syscall_counter;
    void report_prometheus_event(const struct syscall_event &e);

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<syscall_event> &e);
  };

  // convert event to json
  struct json_event_handler : public event_handler<syscall_event>
  {
    std::string to_json(const struct syscall_event &e);
  };

  // used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler
  {
    void handle(tracker_event<syscall_event> &e);
  };

  struct plain_text_event_printer : public event_handler<syscall_event>
  {
    void handle(tracker_event<syscall_event> &e);
  };

  struct csv_event_printer : public event_handler<syscall_event>
  {
  public:
      // 添加构造函数接收 container_manager 引用
      csv_event_printer(container_manager& manager) 
          : manager_ref(manager),
            window_seconds(300)  // 5分钟时间窗口
      {
          roll_file();
      }

      ~csv_event_printer() {
          if (file.is_open()) {
              file.close();
              spdlog::info("Syscall CSV data collection completed. Final file: {}", filename);
          }
      }

      void handle(tracker_event<syscall_event> &e) override 
      {      
          // 检查时间窗口是否到期
          if (std::chrono::system_clock::now() >= window_end_time) {
              roll_file();
          }
          
          if (!file.is_open()) return;

          // 过滤主机数据
          if (e.ct_info.name == "Ubuntu 22.04.5 LTS") 
          {
              return;
          }
          
          std::string syscall_name = "unknown";
          if (e.data.syscall_id < syscall_names_x86_64_size) {
              syscall_name = syscall_names_x86_64[e.data.syscall_id];
          }
          std::string row = fmt::format("{},{},{},{},{},{},{},\"{}\",\"{}\"",
              get_current_time(),
              e.data.pid,
              e.data.ppid,
              e.data.syscall_id,
              syscall_name,
              e.data.comm,
              e.data.occur_times,
              e.ct_info.id,
              e.ct_info.name);
          
          file << row << "\n";
          file.flush();
      }

  private:
      void roll_file() {
          if (file.is_open()) {
              file.close();
              spdlog::info("Rolling Syscall CSV to new time window. Closed: {}", filename);
          }
          
          auto window_start = std::chrono::system_clock::now();
          window_end_time = window_start + std::chrono::seconds(window_seconds);
          auto start_time_t = std::chrono::system_clock::to_time_t(window_start);
          
          std::filesystem::create_directories("agent_data");
          std::stringstream ss;
          ss << "agent_data/syscall_"
            << std::put_time(std::localtime(&start_time_t), "%Y%m%d_%H%M%S") 
            << ".csv";
          filename = ss.str();
          
          file.open(filename);
          if (file.is_open()) {
              file << "timestamp,pid,ppid,syscall_id,syscall_name,comm,occur_times,container_id,container_name\n";
              file.flush();
              spdlog::info("New Syscall CSV collection window started: {}", filename);
          } else {
              spdlog::error("Failed to open Syscall CSV file: {}", filename);
          }
      }

      std::ofstream file;
      std::string filename;
      container_manager& manager_ref;
      const int window_seconds;
      std::chrono::system_clock::time_point window_end_time;
  };
};
#endif
