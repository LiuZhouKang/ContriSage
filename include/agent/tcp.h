#ifndef TCP_CMD_H
#define TCP_CMD_H


#include <string>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>

#include "libbpf_print.h"
#include "model/tracker.h"
#include "prometheus/counter.h"
#include "prometheus_server.h"


extern "C"
{
#include <tcpconnect/tcp_tracker.h>
}

union sender
{
  struct in_addr x4;
  struct in6_addr x6;
};

/// ebpf tcp tracker interface
/// the true implementation is in tcp/tcp_tracker.h

/// trace tcp start and exit
class tcp_tracker : public tracker_with_config<tcp_env, tcp_event>
{
public:
  tcp_tracker(config_data config);

  /// create a tracker with deafult config
  static std::unique_ptr<tcp_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<tcp_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  // start tcp tracker
  void start_tracker();

  // used for prometheus exporter
  struct prometheus_event_handler : public event_handler<tcp_event>
  {
    prometheus::Family<prometheus::Counter> &agent_tcp_v4_counter;
    prometheus::Family<prometheus::Counter> &agent_tcp_v6_counter;
    void report_prometheus_event(tracker_event<tcp_event> &e);

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<tcp_event> &e);
  };
  static int fill_src_dst(sender &s, sender &d,const tcp_event &e);

  // convert event to json
  struct json_event_handler_base : public event_handler<tcp_event>
  {
    std::string to_json(const struct tcp_event &e);
  };

  // used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler_base
  {
    void handle(tracker_event<tcp_event> &e);
  };

  struct plain_text_event_printer : public event_handler<tcp_event>
  {
    void handle(tracker_event<tcp_event> &e);
  };

  struct csv_event_printer : public event_handler<tcp_event>
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
              spdlog::info("TCP CSV data collection completed. Final file: {}", filename);
          }
      }

      void handle(tracker_event<tcp_event> &e) override 
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
          
          char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
          sender s, d;
          
          if (tcp_tracker::fill_src_dst(s, d, e.data) < 0) {
              spdlog::warn("Invalid TCP event");
              return;
          }
          
          std::string row = fmt::format("{},{},{},{},{},{},{},{},\"{}\",\"{}\"",
              get_current_time(),
              e.data.pid,
              e.data.uid,
              e.data.task,
              e.data.af,
              inet_ntop((int)e.data.af, &s, src, sizeof(src)),
              inet_ntop((int)e.data.af, &d, dst, sizeof(dst)),
              ntohs(e.data.dport),
              e.ct_info.id,
              e.ct_info.name);
          
          file << row << "\n";
          file.flush();
      }

  private:
      void roll_file() {
          // 关闭现有文件（如果已打开）
          if (file.is_open()) {
              file.close();
              spdlog::info("Rolling TCP CSV to new time window. Closed: {}", filename);
          }
          
          // 计算新时间窗口
          auto window_start = std::chrono::system_clock::now();
          window_end_time = window_start + std::chrono::seconds(window_seconds);
          auto start_time_t = std::chrono::system_clock::to_time_t(window_start);
          
          // 创建新文件
          std::filesystem::create_directories("agent_data");
          std::stringstream ss;
          ss << "agent_data/tcp_"
            << std::put_time(std::localtime(&start_time_t), "%Y%m%d_%H%M%S") 
            << ".csv";
          filename = ss.str();
          
          file.open(filename);
          if (file.is_open()) {
              file << "timestamp,pid,uid,task,af,src,dst,dport,container_id,container_name\n";
              file.flush();
              spdlog::info("New TCP CSV collection window started: {}", filename);
          } else {
              spdlog::error("Failed to open TCP CSV file: {}", filename);
          }
      }

      std::ofstream file;
      std::string filename;
      const int window_seconds;  // 时间窗口长度(秒)
      std::chrono::system_clock::time_point window_end_time;
  };

private:
    static void handle_tcp_sample_event(void *ctx, int cpu, void *data, unsigned int data_sz);
};
#endif
