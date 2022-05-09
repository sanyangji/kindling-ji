//
// Created by 散养鸡 on 2022/5/9.
//

#ifndef KINDLING_JI_UTILS_H
#define KINDLING_JI_UTILS_H
#include "src/probe/converter/kindling_event.pb.h"
#include "sinsp.h"

using namespace kindling;

Category get_kindling_category(sinsp_evt *pEvt);
Source get_kindling_source(uint16_t etype);
L4Proto get_protocol(scap_l4_proto proto);
ValueType get_type(ppm_param_type type);
string get_kindling_name(sinsp_evt *pEvt);

#endif //KINDLING_JI_UTILS_H
