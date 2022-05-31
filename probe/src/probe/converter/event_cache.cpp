//
// Created by 散养鸡 on 2022/5/20.
//

#include <iostream>
#include "event_cache.h"

bool event_cache::setInfo(uint32_t tid, info_base &info) {
    //std::cout << "try to set: " << info.toStringTs() << std::endl;
    auto it = cache.find(tid);
    if (it == cache.end()) {
        if (info.exit == false) { // skip the first exit one
            auto list = new std::list<info_base>();
             list->emplace_back(info);
            cache[tid] = list;
        }
    } else {
        auto list = it->second;
//        list_lock.lock();
        auto r_it = list->rbegin();
        if (r_it != list->rend()) {
            // update exit event
            if (r_it->exit == false) {
                // pair-event
                if (info.exit == true && r_it->event_type == info.event_type - 1 && info.end_time - r_it->start_time > threshold) {
                    r_it->end_time = info.end_time;
                    r_it->exit = true;
                } else { // lost exit event
                    list->erase((++r_it).base());
                }
            }
        }
        if (info.exit == false) {
            if (list->size() >= list_max_size) {
                list->pop_front();
            }
             list->emplace_back(info);
        }
        if (list->size() > 0) {
//            std::cout << "tid " << tid << " :" <<list->size() << std::endl;
//            std::cout << "first event: " << tid << " " << list->front().toStringTs() << std::endl;
//            std::cout << "latest event: " << tid << " " << list->back().toStringTs() << std::endl;
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
//        std::cout << "before size: " << list->size() << std::endl;
        auto f = list->begin();
        // clear: end_time  <  off.start
        while (f != list->end() && f->end_time < period.first) {
            f = list->erase(f);
        }
        // 搜索 start_time < off.start < end_time
        // 判断 if off.end < end_time && off.end - start_time > threshold -> result.append()
        if (f != list->end()) {
            if (f->start_time < period.first && period.second < f->end_time && period.second - f->start_time > threshold) {
                result.append(f->toString());
            }
        }
//        list_lock.unlock();
        result.append("|");
//        std::cout << "after size: " << list->size() << std::endl;
    }
//    std::cout << "Get tid " << tid << "current map size: " << cache.size() <<endl;
    return result.length() != periods.size() ? result : "";
}

bool event_cache::setThreshold(uint64_t threshold_ms) {
    threshold = threshold_ms * 1000000;
    return true;
}

bool event_cache::clearList(uint32_t tid) {
    auto it = cache.find(tid);
    if (it != cache.end()) {
        if (it->second) {
            delete it->second;
        }
        std::cout << "Clear tid " << tid << "current map size: " << cache.size() <<endl;
        cache.erase(it);
    }
    return true;
}