//
// Created by 散养鸡 on 2022/4/29.
//

#include "cpu_converter.h"
#include <vector>
using namespace std;
using namespace kindling;

cpu_converter::cpu_converter(sinsp *inspector, Profiler *prof, int batch_size, int max_size) : converter(batch_size, max_size), m_inspector(inspector), m_profiler(prof){}

cpu_converter::~cpu_converter() {}

void cpu_converter::convert(void *evt)
{
    sinsp_evt *cpu_evt = static_cast<sinsp_evt*> (evt);
    uint64_t start_time = *reinterpret_cast<uint64_t*> (cpu_evt->get_param_value_raw("start_ts")->m_val);
    uint64_t end_time = *reinterpret_cast<uint64_t*> (cpu_evt->get_param_value_raw("end_ts")->m_val);
    // bool res;
    // if (start_time - end_time >= sample_interval) { // 很长的interval拆分?
    //     res = split();
    // } else {
    //     merge(); // 很小的interval需要不断合并?
    // }
    
    // convert
    auto kevt = get_kindlingEventList()->add_kindling_event_list();
    init_kindling_event(kevt, cpu_evt);
    add_threadinfo(kevt, cpu_evt);
    add_cpu_data(kevt, cpu_evt);
}

void merge()
{
    return;
}
void split()
{
    return;
}

int cpu_converter::init_kindling_event(kindling::KindlingEvent* kevt, sinsp_evt *sevt)
{
    kevt->set_source(TRACEPOINT);
    kevt->set_name("cpu_event");

    return 0;
}

int cpu_converter::add_threadinfo(kindling::KindlingEvent* kevt, sinsp_evt *sevt)
{
    auto s_tinfo = sevt->get_thread_info();
    if (!s_tinfo) {
        return -1;
    }
    auto k_tinfo = kevt->mutable_ctx()->mutable_thread_info();
    k_tinfo->set_pid(s_tinfo->m_pid);
    k_tinfo->set_tid(s_tinfo->m_tid);
    k_tinfo->set_comm(s_tinfo->m_comm);
    // k_tinfo->set_container_id(s_tinfo->m_container_id);
    return 0;
}

int cpu_converter::add_cpu_data(KindlingEvent* kevt, sinsp_evt *sevt)
{
    uint64_t start_time = *reinterpret_cast<uint64_t*> (sevt->get_param_value_raw("start_ts")->m_val);
    uint64_t end_time = *reinterpret_cast<uint64_t*> (sevt->get_param_value_raw("end_ts")->m_val);
    uint32_t cnt = *reinterpret_cast<uint32_t*> (sevt->get_param_value_raw("cnt")->m_val);
    uint64_t *time_specs = reinterpret_cast<uint64_t *> (sevt->get_param_value_raw("time_specs")->m_val);
    uint8_t *time_type = reinterpret_cast<uint8_t *> (sevt->get_param_value_raw("time_type")->m_val);
    cpu_data c_data;
    vector<pair<uint64_t, uint64_t>> times;

    uint64_t on_total_time = 0, off_total_time = 0;
    uint64_t start = start_time;
    for (int i = 0; i < cnt; i++) {
        if (time_type[i] == 0) {
            c_data.on_total_time += time_specs[i];
            times.push_back({start, start + time_specs[i] * 1000});
        } else {
            c_data.off_total_time += time_specs[i];
        }
        start = start + time_specs[i] * 1000;
        c_data.time_specs += (to_string(time_specs[i]) + ",");
        c_data.time_type += (to_string(time_type[i]) +  ",");
    }
    // on_total_time
    auto off_attr = kevt->add_user_attributes();
    off_attr->set_key("on_total_time");
    off_attr->set_value(&c_data.on_total_time, 8);
    off_attr->set_value_type(UINT64);

    // off_total_time
    off_attr = kevt->add_user_attributes();
    off_attr->set_key("off_total_time");
    off_attr->set_value(&c_data.off_total_time, 8);
    off_attr->set_value_type(UINT64);

    // start_time
    off_attr = kevt->add_user_attributes();
    off_attr->set_key("start_time");
    off_attr->set_value(&c_data.start_time, 8);
    off_attr->set_value_type(UINT64);

    // end_time
    off_attr = kevt->add_user_attributes();
    off_attr->set_key("end_time");
    off_attr->set_value(&c_data.end_time, 8);
    off_attr->set_value_type(UINT64);

    // time_specs
    off_attr = kevt->add_user_attributes();
    off_attr->set_key("type_specs");
    off_attr->set_value(c_data.time_specs);
    off_attr->set_value_type(CHARBUF);

    // time_type
    off_attr = kevt->add_user_attributes();
    off_attr->set_key("time_type");
    off_attr->set_value(c_data.time_type);
    off_attr->set_value_type(CHARBUF);

    // on_stack
    auto on_attr = kevt->add_user_attributes();
    auto s_tinfo = sevt->get_thread_info();
    string data = m_profiler->GetOnCpuData(s_tinfo->m_tid, times);
    on_attr->set_key("on_stack");
    on_attr->set_value(data);
    on_attr->set_value_type(CHARBUF);
    // merge();
    // analyse()

    return 0;
}