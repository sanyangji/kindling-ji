#ifndef CPU_CONVERTER_H
#define CPU_CONVERTER_H
#include "src/probe/converter/converter.h"
#include "src/probe/profile/profiler.h"
#include "src/probe/log/log_info.h"
#include "src/probe/converter/event_cache.h"
#include <string>
#include <map>
#include "sinsp.h"
class cpu_data {
public:
    uint64_t start_time;
    uint64_t end_time;
    uint64_t on_total_time;
    uint64_t off_total_time;
    string time_specs;
    string on_stack;
    string time_type;
    uint32_t tid;
};

class cpu_converter : public converter
{
public:
    cpu_converter(sinsp *inspector, Profiler *prof, LogCache *log, int batch_size, int max_size);
    ~cpu_converter();
    void convert(void *evt);
    bool Cache(sinsp_evt *evt);
private:
    int init_kindling_event(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
    int add_threadinfo(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
    int add_cpu_data(kindling::KindlingEvent* kevt, sinsp_evt *sevt);

    int32_t set_boot_time(uint64_t *boot_time);

    sinsp *m_inspector;
    Profiler *m_profiler;
    LogCache *m_log;
    uint64_t sample_interval;
    event_cache *file_cache;
    event_cache *net_cache;
};

#endif //CPU_CONVERTER_H
