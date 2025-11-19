#ifndef PROCESS_CMD_H
#define PROCESS_CMD_H


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
#include <process/process_tracker.h>
}

/// ebpf process tracker interface

/// the true implementation is in process/process_tracker.h
///
/// trace process start and exit
struct process_tracker : public tracker_with_config<process_env, process_event>
{
  process_tracker(config_data config);

  /// create a tracker with deafult config
  static std::unique_ptr<process_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<process_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  /// start process tracker
  void start_tracker();

  /// used for prometheus exporter
  struct prometheus_event_handler : public event_handler<process_event>
  {
    prometheus::Family<prometheus::Counter> &agent_process_start_counter;
    prometheus::Family<prometheus::Counter> &agent_process_exit_counter;
    void report_prometheus_event(const struct process_event &e, const struct container_info& ct_info);

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<process_event> &e);
  };

  /// convert event to json
  struct json_event_handler_base : public event_handler<process_event>
  {
    std::string to_json(const struct process_event &e);
  };

  /// used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler_base
  {
    void handle(tracker_event<process_event> &e);
  };

  struct plain_text_event_printer : public event_handler<process_event>
  {
    void handle(tracker_event<process_event> &e);
  };

  // CSV 事件处理器
  struct csv_event_printer : public event_handler<process_event>
  {
  public:
      csv_event_printer() 
          : window_seconds(300)  // 5分钟时间窗口
      {
          roll_file();
      }

      ~csv_event_printer() {
          if (file.is_open()) {
              file.close();
              spdlog::info("Process CSV data collection completed. Final file: {}", filename);
          }
      }

      void handle(tracker_event<process_event> &e) override 
      {
          // 检查时间窗口是否到期
          if (std::chrono::system_clock::now() >= window_end_time) {
              roll_file();
          }
          
          if (!file.is_open()) return;

          //过滤主机数据
          if (e.ct_info.name == "Ubuntu 22.04.5 LTS") 
          {
              return;
          }
          
          std::string event_type = e.data.exit_event ? "exit" : "start";
          std::string row = fmt::format("{},{},{},{},{},{},{},{},{},\"{}\",\"{}\",\"{}\",\"{}\"",
              event_type,
              get_current_time(),
              e.data.common.pid,
              e.data.common.ppid,
              e.data.common.cgroup_id,
              e.data.common.user_namespace_id,
              e.data.common.pid_namespace_id,
              e.data.common.mount_namespace_id,
              e.data.exit_event ? e.data.exit_code : 0,
              e.data.comm,
              e.data.filename,
              e.ct_info.id,
              e.ct_info.name);
          
          file << row << "\n";
          file.flush();
      }

  private:
      void roll_file() {
          if (file.is_open()) {
              file.close();
              spdlog::info("Rolling Process CSV to new time window. Closed: {}", filename);
          }
          
          auto window_start = std::chrono::system_clock::now();
          window_end_time = window_start + std::chrono::seconds(window_seconds);
          auto start_time_t = std::chrono::system_clock::to_time_t(window_start);
          
          std::filesystem::create_directories("agent_data");
          std::stringstream ss;
          ss << "agent_data/process_"
            << std::put_time(std::localtime(&start_time_t), "%Y%m%d_%H%M%S") 
            << ".csv";
          filename = ss.str();
          
          file.open(filename);
          if (file.is_open()) {
              file << "event,timestamp,pid,ppid,cgroup_id,user_ns,pid_ns,mount_ns,exit_code,comm,filename,container_id,container_name\n";
              file.flush();
              spdlog::info("New Process CSV collection window started: {}", filename);
          } else {
              spdlog::error("Failed to open Process CSV file: {}", filename);
          }
      }

      std::ofstream file;
      std::string filename;
      const int window_seconds;
      std::chrono::system_clock::time_point window_end_time;
  };
};

#endif