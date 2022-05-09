#ifndef CPU_CONVERTER_H
#define CPU_CONVERTER_H
#include "src/probe/converter/converter.h"
#include "src/probe/profile/profiler.h"
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
    cpu_converter(sinsp *inspector, int batch_size, int max_size);
    cpu_converter(sinsp *inspector, Profiler *prof, int batch_size, int max_size);
    ~cpu_converter();
    void convert(void *evt);
    map<uint32_t, cpu_data> cpu_cache;
private:
    int init_kindling_event(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
    int add_threadinfo(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
    int add_cpu_data(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
    sinsp *m_inspector;
    Profiler *m_profiler;
    uint64_t sample_interval;
    // on cpu_data
    // call m->get_data()
};


#endif //CPU_CONVERTER_H