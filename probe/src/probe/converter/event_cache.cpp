//
// Created by 散养鸡 on 2022/5/20.
//

#include <iostream>
#include "event_cache.h"

bool event_cache::setInfo(uint32_t tid, info_base &info) {
    //std::cout << "try to set: " << info.toStringTs() << std::endl;
    auto it = cache.find(tid);
    if (it == cache.end()) {
        if (info.start_time != 0) {
            auto list = new std::list<info_base>();
            list->emplace_back(std::move(info));
            cache[tid] = list;
        }
    } else {
        auto list = it->second;
//        list_lock.lock();
        auto it = list->rbegin();
        if (it != list->rend()){
            // update exit event
            if (it->exit == false) {
                it->end_time = info.end_time;
                it->exit = true;
            } else { // new event
                list->emplace_back(std::move(info));
            }
        } else { // empty list
            list->emplace_back(std::move(info));
        }
        //std::cout << "current size: " << list->size() << std::endl;
        if (list->size() > 0) {
            //std::cout << "latest event: " << tid << " " << list->back().toStringTs() << std::endl;
        }
//        list_lock.unlock();
    }
    return true;
}
string event_cache::GetInfo(uint32_t tid, vector<pair<uint64_t, uint64_t>> &periods, vector<uint8_t> &off_type) {
    string result = "";
    // find
    auto it = cache.find(tid);
    if (it == cache.end()) {
        return result;
    }
    for (int i = 0; i < (int) periods.size(); i++) {
        auto period = periods[i];
        auto list = it->second;
        if (off_type[i] != event_type) {
            result.append("|");
            continue;
        }
        //std::cout << "query info: " << period.first << "->" << period.second << std::endl;

//        list_lock.lock();
        auto f = list->begin();
        // clear: end_time  <  off.start
        while (f != list->end() && f->end_time < period.first) {
            f = list->erase(f);
        }
        // 搜索 start_time < off.start < end_time
        // 判断 if off.end < end_time result.append()
        if (f != list->end()) {
            if (f->start_time < period.first && period.second < f->end_time) {
                result.append(f->toString());
            }
        }
//        list_lock.unlock();
        result.append("|");
    }
    return result.length() != periods.size() ? result : "";
}
