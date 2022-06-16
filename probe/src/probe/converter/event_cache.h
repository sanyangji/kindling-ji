//
// Created by 散养鸡 on 2022/5/20.
//

#ifndef KINDLING_EVENT_CACHE_H
#define KINDLING_EVENT_CACHE_H
#include <map>
#include <list>
#include <vector>
#include "sinsp.h"
class info_base {
public:
    info_base() {
        start_time = 0;
        end_time = INTMAX_MAX; // 如果没有收到exit时间，认为是符合要求的
        size = 0;
        exit = false;
    }
    virtual ~info_base() {
//        std::cout << "delete" << toStringTs() << std::endl;
    }
    uint64_t start_time;
    uint64_t end_time;
    bool exit;
    uint16_t event_type;
    string name;
    uint32_t size;
    string operation_type;
    string relate_id;
    virtual string toString() = 0;
    string toStringTs() {
        return to_string(start_time) + "#" + to_string(end_time) + "#" + operation_type + "#" + name + "#" + to_string(size) + "#" + (exit==true ? "true" : "false");
    }
};

class file_info : public info_base {
public:
    file_info() {}
    ~file_info() {}
    string toString() {
        return operation_type + "#" + name + "#" + to_string(size);
    }
};

class net_info : public info_base {
public:
    net_info() {}
    ~net_info() {}
    string toString() {
        return operation_type + "#" + name + "#" + to_string(size);
    }
};
class epoll_info : public info_base {
public:
    epoll_info() {}
    ~epoll_info() {}
    vector<int> fds;
    string toString() {
        return relate_id;
    }
};
class event_cache {
public:
    event_cache(uint8_t type) : event_type(type) {
        threshold = 100000; // 100us
    }
    string GetInfo(uint32_t tid, pair<uint64_t, uint64_t> &period, uint8_t off_type);
    bool setThreshold(uint64_t thres);
    bool setInfo(uint32_t tid, info_base *info);
    bool send();
    bool clearList(uint32_t tid);

    std::mutex list_lock;
    unordered_map<uint32_t, list<info_base* >* > cache;
    uint8_t event_type;
    std::atomic_ullong threshold;
    uint32_t list_max_size = 16;
};
class epoll_event_cache : public event_cache {
public:
    epoll_event_cache(uint8_t type) : event_cache(type) {}
    bool setInfo(sinsp_evt *evt);
    bool SetLastEpollCache(uint32_t tid, int64_t fd, info_base *info);
};
#endif //KINDLING_EVENT_CACHE_H
