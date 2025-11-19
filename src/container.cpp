#include <dirent.h>
#include <spdlog/spdlog.h>

#include <cstring>
#include <regex>
#include <sstream>

#include "agent/container_manager.h"
#include "httplib.h"
#include "json.hpp"

extern "C"
{
#include <container/container.h>
#include <process/process_tracker.h>
#include <unistd.h>
}

using namespace nlohmann;

container_manager::container_client::container_client() : dockerd_client("unix:/var/run/docker.sock")
{
  dockerd_client.set_default_headers({ { "Host", "localhost" } });
}

std::string container_manager::container_client::list_all_containers()
{
  std::stringstream resp_stream;
  auto response = dockerd_client.Get("/containers/json");
  resp_stream << response->body;
  return resp_stream.str();
}

std::string container_manager::container_client::list_all_process_running_in_container(const std::string& container_id)
{
  std::stringstream resp_stream;
  auto response = dockerd_client.Get("/containers/" + container_id + "/top");
  resp_stream << response->body;
  return resp_stream.str();
}

std::string container_manager::container_client::inspect_container(const std::string& container_id)
{
  std::stringstream resp_stream;
  auto response = dockerd_client.Get("/containers/" + container_id + "/json");
  resp_stream << response->body;
  return resp_stream.str();
}

container_info container_manager::container_client::get_os_container_info()
{
  try
  {
    json res_json;
    std::stringstream resp_stream;
    auto response = dockerd_client.Get("/info");
    resp_stream << response->body;
    resp_stream >> res_json;
    spdlog::info("Docker OS info: {}", res_json["OperatingSystem"].get<std::string>());
    return container_info{
      .id = "0",
      .name = res_json["OperatingSystem"].get<std::string>(),
    };
  }
  catch (...)
  {
    spdlog::error("Failed to get os container info, is dockerd running?");
    return container_info{
      .id = "0",
      .name = "Bare metal",
    };
  }
}

container_info container_manager::get_container_info_for_pid(int pid) const
{
  auto res = info_map.get(pid);
  if (res)
  {
    return res->info;
  }
  return os_info;
}

void container_manager::init()
{
  // get os info base
  os_info = client.get_os_container_info();
  spdlog::info("OS container info: {}", os_info.name);
  // get all process info into the table
  get_all_process_info();
  // get all container process into the table
  update_container_map_data();
}

container_manager::container_manager()
{
}

std::int64_t get_process_namespace(const char* type, int pid)
{
  std::string path = "/proc/" + std::to_string(pid) + "/ns/" + type;
  constexpr auto BUFFER_SIZE = 128;
  char buffer[BUFFER_SIZE];
  ssize_t res = 0;
  std::int64_t ns = 0;

  res = readlink(path.c_str(), buffer, 100);
  if (res < 0)
  {
    // spdlog::error("Failed to readlink {}", path);
    // This is common for short lived processes,
    // so don't log an error
    return 0;
  }
  const std::string s = buffer;
  std::regex rgx(".*:\\[([0-9]+)\\]");
  std::smatch match;

  if (std::regex_search(s.begin(), s.end(), match, rgx))
  {
    ns = std::stoll(match[1].str());
  }
  return ns;
}

// fill the process common event with namespace info
common_event get_process_common_event(int pid)
{
  common_event info = { 0 };
  info.pid = pid;
  info.pid_namespace_id = get_process_namespace("pid", pid);
  info.mount_namespace_id = get_process_namespace("mnt", pid);
  info.user_namespace_id = get_process_namespace("user", pid);
  return info;
}

void container_manager::get_all_process_info(void)
{
  DIR* dir = nullptr;

  if (!(dir = opendir("/proc")))
  {
    spdlog::error("Failed to open /proc");
    return;
  }
  while (dirent* dirp = readdir(dir))
  {
    // is this a directory?
    if (dirp->d_type != DT_DIR)
      continue;
    try
    {
      int pid = std::atoi(dirp->d_name);
      if (pid == 0)
      {
        continue;
      }
      info_map.insert(pid, process_container_info_data{ get_process_common_event(pid), os_info });
    }
    catch (...)
    {
      continue;
    }
  }
  int res = closedir(dir);
  if (res == -1)
  {
    spdlog::error("Failed to close /proc");
    return;
  }
}

void container_manager::update_container_map_data(void)
{
  auto response = client.list_all_containers();
  json containers_json = json::parse(response);
  for (const auto c : containers_json)
  {
    container_info info = { c["Id"], c["Names"][0], container_status_from_str(c["State"]) };

    json process_resp = json::parse(client.list_all_process_running_in_container(info.id));
    for (const auto p : process_resp["Processes"])
    {
      int pid = std::atoi(std::string(p[1]).c_str());
      int ppid = std::atoi(std::string(p[2]).c_str());

      auto map_data = info_map.get(pid);
      if (map_data)
      {
        // update existing data with new container info
        map_data->common.pid = pid;
        map_data->common.ppid = ppid;
        map_data->info = info;
        info_map.insert(pid, *map_data);
      }
      else
      {
        auto common_e = get_process_common_event(pid);
        common_e.ppid = ppid;
        info_map.insert(pid, process_container_info_data{ common_e, info });
      }
    }
  }
}

static bool operator==(const common_event& a, const common_event& b)
{
  return a.pid_namespace_id == b.pid_namespace_id && a.user_namespace_id == b.user_namespace_id &&
         a.mount_namespace_id == b.mount_namespace_id;
}

void container_manager::container_tracking_handler::handle(tracker_event<process_event>& e)
{
  if (e.data.exit_event)
  {
    // process exit; preserve container info before removal so exporters can see it
    e.ct_info = manager.get_container_info_for_pid(e.data.common.pid);
    manager.info_map.remove(e.data.common.pid);
    return; // do not overwrite ct_info below
  }
  else
  {
    // process start;
    auto this_info = manager.info_map.get(e.data.common.pid);
    if (this_info)
    {
      // find the pid and update the map
      manager.info_map.insert(
          e.data.common.pid, process_container_info_data{ .common = e.data.common, .info = this_info->info });
      return;
    }

    // find ppid info
    int ppid = e.data.common.ppid;
    auto pp_info = manager.info_map.get(ppid);
    if (pp_info)
    {
      // reinsert the info from the parent process
      auto data = *pp_info;
      if (!(data.common == e.data.common))
      {
        // not same namespace, update container info.
        spdlog::info(
            "different namespace from parent process, update info for pid {} name {}.", e.data.common.pid, e.data.comm);
        manager.update_container_map_data();
      }
      data.common = e.data.common;
      manager.info_map.insert(e.data.common.pid, data);
      return;
    }
    // no parent info, no this info
    spdlog::info("No parent info and this pid container info: pid {} name {}", e.data.common.pid, e.data.comm);
    // no info, insert os info to the map
    manager.info_map.insert(
        e.data.common.pid, process_container_info_data{ .common = e.data.common, .info = manager.os_info });
    // add new info to ppid
    manager.info_map.insert(
        e.data.common.ppid, process_container_info_data{ get_process_common_event(e.data.common.ppid), manager.os_info });
  }
  // fill ct_info for start events
  e.ct_info = manager.get_container_info_for_pid(e.data.common.pid);
}

// void container_manager::container_tracking_handler::handle(tracker_event<process_event>& e) {
//   if (e.data.exit_event) {
//     manager.info_map.remove(e.data.common.pid);
//   } else {
//     // 检查当前进程是否已有容器信息
//     auto this_info = manager.info_map.get(e.data.common.pid);
//     if (this_info) {
//       manager.info_map.insert(
//           e.data.common.pid, 
//           process_container_info_data{ e.data.common, this_info->info }
//       );
//       return;
//     }

//     // 获取父进程容器信息
//     int ppid = e.data.common.ppid;
//     auto pp_info = manager.info_map.get(ppid);
    
//     if (pp_info) {
//       // +++ 修复1: 直接继承父进程容器信息 +++
//       manager.info_map.insert(
//           e.data.common.pid,
//           process_container_info_data{ e.data.common, pp_info->info }
//       );
//       // +++ 修复2: 即使命名空间不同也先继承，后续异步更新 +++
//       if (!(pp_info->common == e.data.common)) {
//         spdlog::info(
//             "different namespace from parent process, async update for pid {} name {}.",
//             e.data.common.pid, e.data.comm);
        
//         // 异步更新容器映射
//         std::thread([this]() {
//           manager.update_container_map_data();
//         }).detach();
//       }
//       // -----------------------------------
//     } else {
//       // 无父进程信息时使用OS信息
//       manager.info_map.insert(
//           e.data.common.pid, 
//           process_container_info_data{ e.data.common, manager.os_info }
//       );
//     }
//   }
//   // +++ 修复3: 确保事件使用最新的容器信息 +++
//   e.ct_info = manager.get_container_info_for_pid(e.data.common.pid);
// }

// void container_manager::container_tracking_handler::handle(tracker_event<process_event>& e) {
//   if (e.data.exit_event) {
//     manager.info_map.remove(e.data.common.pid);
//   } else {
//     // 检查当前进程是否已有容器信息
//     auto this_info = manager.info_map.get(e.data.common.pid);
//     if (this_info) {
//       manager.info_map.insert(
//           e.data.common.pid, 
//           process_container_info_data{ e.data.common, this_info->info }
//       );
//       return;
//     }

//     // 获取父进程容器信息
//     int ppid = e.data.common.ppid;
//     auto pp_info = manager.info_map.get(ppid);
    
//     if (pp_info) {
//       // +++ 新增: 直接继承父进程容器信息 +++
//       if (pp_info->info.id != "0") { // 父进程在容器内
//         manager.info_map.insert(
//             e.data.common.pid,
//             process_container_info_data{ e.data.common, pp_info->info }
//         );
//         return;
//       }
//       // -----------------------------------
      
//       if (!(pp_info->common == e.data.common)) {
//         spdlog::info(
//             "different namespace from parent process, update info for pid {} name {}.",
//             e.data.common.pid, e.data.comm);
        
//         // 更新容器映射
//         manager.update_container_map_data();
        
//         // +++ 新增: 更新后再次尝试获取 +++
//         auto updated_info = manager.info_map.get(e.data.common.pid);
//         if (updated_info) {
//           manager.info_map.insert(
//               e.data.common.pid, 
//               process_container_info_data{ e.data.common, updated_info->info }
//           );
//         } else {
//           // 若仍未找到，使用父进程容器信息
//           manager.info_map.insert(
//               e.data.common.pid,
//               process_container_info_data{ e.data.common, pp_info->info }
//           );
//         }
//         // -----------------------------------
//       }
//     } else {
//       // 无父进程信息时使用OS信息
//       manager.info_map.insert(
//           e.data.common.pid, 
//           process_container_info_data{ e.data.common, manager.os_info }
//       );
//     }
//   }
//   e.ct_info = manager.get_container_info_for_pid(e.data.common.pid);
// }

// void container_manager::container_tracking_handler::handle(tracker_event<process_event>& e) {
//     if (e.data.exit_event) {
//         manager.info_map.remove(e.data.common.pid);
//     } else {
//         // 检查当前进程是否已有容器信息
//         auto this_info = manager.info_map.get(e.data.common.pid);
//         if (this_info) {
//             // 如果已有信息，更新common字段
//             manager.info_map.insert(
//                 e.data.common.pid, 
//                 process_container_info_data{ e.data.common, this_info->info }
//             );
//         } else {
//             // 获取父进程容器信息
//             int ppid = e.data.common.ppid;
//             auto pp_info = manager.info_map.get(ppid);
//             container_info info = manager.os_info; // 默认使用OS信息

//             if (pp_info) {
//                 // 先继承父进程的容器信息
//                 info = pp_info->info;
//             }

//             // 插入当前进程的信息
//             manager.info_map.insert(
//                 e.data.common.pid,
//                 process_container_info_data{ e.data.common, info }
//             );

//             // 如果父进程存在且命名空间不同，则异步更新容器映射（因为可能是新容器）
//             if (pp_info && !(pp_info->common == e.data.common)) {
//                 spdlog::info(
//                     "different namespace from parent process, async update for pid {} name {}.",
//                     e.data.common.pid, e.data.comm);
                
//                 // 异步更新容器映射
//                 std::thread([this]() {
//                     manager.update_container_map_data();
//                 }).detach();
//             }
//         }
//     }
//     // 确保事件使用最新的容器信息
//     e.ct_info = manager.get_container_info_for_pid(e.data.common.pid);
// }


// void container_manager::container_tracking_handler::handle(tracker_event<process_event>& e) {
//     if (e.data.exit_event) {
//         // 生成退出事件记录
//         e.ct_info = manager.get_container_info_for_pid(e.data.common.pid);
//         manager.info_map.remove(e.data.common.pid);
//     } else {
//         // 获取父进程容器信息
//         int ppid = e.data.common.ppid;
//         auto pp_info = manager.info_map.get(ppid);
//         container_info info = manager.os_info;

//         if (pp_info) {
//             // 直接继承父进程的容器信息
//             info = pp_info->info;
//         }

//         // 插入当前进程信息
//         manager.info_map.insert(
//             e.data.common.pid,
//             process_container_info_data{e.data.common, info}
//         );

//         // 如果命名空间不同，异步更新容器映射
//         if (pp_info && !(pp_info->common == e.data.common)) {
//             std::thread([&manager = manager]() {
//                 manager.update_container_map_data();
//             }).detach();
//         }
//     }
//     // 确保事件使用最新的容器信息
//     e.ct_info = manager.get_container_info_for_pid(e.data.common.pid);
// }
