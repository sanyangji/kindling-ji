#ifndef KINDLING_PROBE_SYSDIG_CONVERTER_H
#define KINDLING_PROBE_SYSDIG_CONVERTER_H
#include "sinsp.h"
#include "src/probe/converter/converter.h"
using namespace kindling;

class sysdig_converter : public converter
{
public:
    void convert(void *evt);
    sysdig_converter(sinsp *inspector);
    sysdig_converter(sinsp *inspector, int batch_size, int max_size);
    ~sysdig_converter();
private:
    // set source, name, timestamp, category according to list
	int init_kindling_event(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_native_attributes(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_user_attributes(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_fdinfo(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_threadinfo(kindling::KindlingEvent* kevt, sinsp_evt *sevt);

	sinsp *m_inspector;

    int setTuple(kindling::KindlingEvent* kevt, const sinsp_evt_param *pParam);
};

#endif //KINDLING_PROBE_SYSDIG_CONVERTER_H
