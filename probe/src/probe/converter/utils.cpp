//
// Created by 散养鸡 on 2022/5/9.
//

#include "utils.h"

string get_kindling_name(sinsp_evt *evt) {
    return evt->get_name();
}

Source get_kindling_source(uint16_t etype) {
    if (PPME_IS_ENTER(etype)) {
        switch (etype) {
            case PPME_PROCEXIT_E:
            case PPME_SCHEDSWITCH_6_E:
            case PPME_SYSDIGEVENT_E:
            case PPME_CONTAINER_E:
            case PPME_PROCINFO_E:
            case PPME_SCHEDSWITCH_1_E:
            case PPME_DROP_E:
            case PPME_PROCEXIT_1_E:
            case PPME_CPU_HOTPLUG_E:
            case PPME_K8S_E:
            case PPME_TRACER_E:
            case PPME_MESOS_E:
            case PPME_CONTAINER_JSON_E:
            case PPME_NOTIFICATION_E:
            case PPME_INFRASTRUCTURE_EVENT_E:
            case PPME_PAGE_FAULT_E:
                return SOURCE_UNKNOWN;
            case PPME_TCP_RCV_ESTABLISHED_E:
            case PPME_TCP_CLOSE_E:
            case PPME_TCP_DROP_E:
            case PPME_TCP_RETRANCESMIT_SKB_E:
                return KRPOBE;
                // TODO add cases of tracepoint, kprobe, uprobe
            default:
                return SYSCALL_ENTER;
        }
    } else {
        switch (etype) {
            case PPME_CONTAINER_X:
            case PPME_PROCINFO_X:
            case PPME_SCHEDSWITCH_1_X:
            case PPME_DROP_X:
            case PPME_CPU_HOTPLUG_X:
            case PPME_K8S_X:
            case PPME_TRACER_X:
            case PPME_MESOS_X:
            case PPME_CONTAINER_JSON_X:
            case PPME_NOTIFICATION_X:
            case PPME_INFRASTRUCTURE_EVENT_X:
            case PPME_PAGE_FAULT_X:
                return SOURCE_UNKNOWN;
                // TODO add cases of tracepoint, kprobe, uprobe
            default:
                return SYSCALL_EXIT;
        }
    }
}

Category get_kindling_category(sinsp_evt *sEvt) {
    sinsp_evt::category cat;
    sEvt->get_category(&cat);
    switch (cat.m_category) {
        case EC_OTHER:
            return CAT_OTHER;
        case EC_FILE:
            return CAT_FILE;
        case EC_NET:
            return CAT_NET;
        case EC_IPC:
            return CAT_IPC;
        case EC_MEMORY:
            return CAT_MEMORY;
        case EC_PROCESS:
            return CAT_PROCESS;
        case EC_SLEEP:
            return CAT_SLEEP;
        case EC_SYSTEM:
            return CAT_SYSTEM;
        case EC_SIGNAL:
            return CAT_SIGNAL;
        case EC_USER:
            return CAT_USER;
        case EC_TIME:
            return CAT_TIME;
        case EC_IO_READ:
        case EC_IO_WRITE:
        case EC_IO_OTHER: {
            switch (cat.m_subcategory) {
                case sinsp_evt::SC_FILE:
                    return CAT_FILE;
                case sinsp_evt::SC_NET:
                    return CAT_NET;
                case sinsp_evt::SC_IPC:
                    return CAT_IPC;
                default:
                    return CAT_OTHER;
            }
        }
        default:
            return CAT_OTHER;
    }
}

L4Proto get_protocol(scap_l4_proto proto) {
    switch (proto) {
        case SCAP_L4_TCP:
            return TCP;
        case SCAP_L4_UDP:
            return UDP;
        case SCAP_L4_ICMP:
            return ICMP;
        case SCAP_L4_RAW:
            return RAW;
        default:
            return UNKNOWN;
    }
}

ValueType get_type(ppm_param_type type) {
    switch (type) {
        case PT_INT8:
            return INT8;
        case PT_INT16:
            return INT16;
        case PT_INT32:
            return INT32;
        case PT_INT64:
        case PT_FD:
        case PT_PID:
        case PT_ERRNO:
            return INT64;
        case PT_FLAGS8:
        case PT_UINT8:
        case PT_SIGTYPE:
            return UINT8;
        case PT_FLAGS16:
        case PT_UINT16:
        case PT_SYSCALLID:
            return UINT16;
        case PT_UINT32:
        case PT_FLAGS32:
        case PT_MODE:
        case PT_UID:
        case PT_GID:
        case PT_BOOL:
        case PT_SIGSET:
            return UINT32;
        case PT_UINT64:
        case PT_RELTIME:
        case PT_ABSTIME:
            return UINT64;
        case PT_CHARBUF:
        case PT_FSPATH:
            return CHARBUF;
        case PT_BYTEBUF:
            return BYTEBUF;
        case PT_DOUBLE:
            return DOUBLE;
        case PT_SOCKADDR:
        case PT_SOCKTUPLE:
        case PT_FDLIST:
        default:
            return BYTEBUF;
    }
}