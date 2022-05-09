#include "src/probe/profile/flame_graph.h"
#include "src/probe/profile/bcc/symbol.h"
#include <cstddef>
#include <sys/types.h>
#include <time.h>
#include <string.h>

struct FlameGraphCtx{
    string seperator_stack_;
    string seperator_count_;
    string seperator_next_;

    int cache_keep_time_;
    int max_depth_;
    BPFSymbolTable *symbol_table_ = new BPFSymbolTable();;
} flame_graph_ctx;

SampleData::SampleData() {}

SampleData::SampleData(struct sample_type_data *sample_data) {
    pid_ = sample_data->tid_entry.pid;
    tid_ = sample_data->tid_entry.tid;
    time_ = sample_data->time;
    nr_ = sample_data->callchain.nr;
    memcpy(&ips_[0], sample_data->callchain.ips, nr_ * sizeof(sample_data->callchain.ips[0]));
}

string SampleData::addThreadInfo(string call_stack) {
    if (flame_graph_ctx.cache_keep_time_ == 0) {
        call_stack.insert(0, flame_graph_ctx.seperator_stack_);
        call_stack.insert(0, std::to_string(tid_));
        call_stack.insert(0, flame_graph_ctx.seperator_stack_);
        call_stack.insert(0, std::to_string(pid_));
    }
    return call_stack;
}

string SampleData::GetString() {
    string call_stack = "";
    bool kernel = false, user = false, seperator = false;
    int depth = 0, pid = 0;
    __u64 ip = 0;
    for (__u64 i = 0; i < nr_; i++) {
        ip = ips_[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kernel = true;
            user = false; 
            pid = -1;
            continue;
        } else if (ip == PERF_CONTEXT_USER) {
            kernel = false;
            user = true;
            pid = pid_;
            continue;
        }
        if (kernel || user) {
            if (seperator) {
                call_stack.insert(0, flame_graph_ctx.seperator_stack_);
            } else {
                seperator = true;
            }
            call_stack.insert(0, flame_graph_ctx.symbol_table_->GetSymbol(ip, pid));
            if (++depth >= flame_graph_ctx.max_depth_) {
                return addThreadInfo(call_stack);
            }
        }
    }

    return addThreadInfo(call_stack);
}

AggregateData::AggregateData(__u32 tid) {
    tid_ = tid;
}

void AggregateData::Aggregate(void* data) {
    SampleData *sample_data = (SampleData*)data;
    if (sample_data->pid_ == 0 || (tid_ > 0 && sample_data->tid_ != tid_)) {
        return;
    }

    string call_stack = sample_data->GetString();
    auto itr = agg_count_map_.find(call_stack);
    if (itr == agg_count_map_.end()) {
        agg_count_map_.insert(std::make_pair(call_stack, 1));
    } else {
        itr->second = itr->second + 1;
    }
}

string AggregateData::ToString() {
    string result = "";
    
    bool seperator = false;
    map<string, int>::iterator itr;
    for (itr = agg_count_map_.begin(); itr != agg_count_map_.end(); itr++) {
        if (seperator) {
            result.append(flame_graph_ctx.seperator_next_);
        } else {
            seperator = true;
        }
        result.append(itr->first);
        result.append(flame_graph_ctx.seperator_count_);
        result.append(std::to_string(itr->second));
    }
    return result;
}

static void aggTidData(void* object, void* value) {
    AggregateData* pObject = (AggregateData*) object;
    pObject->Aggregate(value);
}

FlameGraph::FlameGraph(int cache_keep_time) {
    sample_datas_ = new RingBuffers<SampleData>(1000);

    flame_graph_ctx.cache_keep_time_ = cache_keep_time;
    if (cache_keep_time > 0) {
        flame_graph_ctx.seperator_stack_ = "#";
        flame_graph_ctx.seperator_count_ = "@";
        flame_graph_ctx.seperator_next_ = "|";
        flame_graph_ctx.max_depth_ = 1;
    } else  {
        flame_graph_ctx.cache_keep_time_ = 0;
        flame_graph_ctx.seperator_stack_ = ";";
        flame_graph_ctx.seperator_count_ = " ";
        flame_graph_ctx.seperator_next_ = "\n";
        flame_graph_ctx.max_depth_ = 20;
    }
}

FlameGraph::~FlameGraph() {
    delete &sample_datas_;
}

void FlameGraph::EnableFlameFile(bool file) {
    write_flame_graph_ = file;
    if (file) {
        resetLogFile();
    }
}

void FlameGraph::RecordSampleData(__u64 timestamp, struct sample_type_data *sample_data) {
    if (sample_data->callchain.nr > 256) {
        fprintf(stdout, "[Ignore Sample Data] Pid: %d, Tid: %d, Nr: %lld\n",sample_data->tid_entry.pid, sample_data->tid_entry.tid, sample_data->callchain.nr);
        return;
    }
    SampleData *data = new SampleData(sample_data);
    sample_datas_->add(timestamp, *data);
}

void FlameGraph::CollectData(__u64 timestamp) {
    if (flame_graph_ctx.cache_keep_time_ == 0) {
        AggregateData *aggregateData = new AggregateData(0);
        sample_datas_->collect(last_collect_time_, timestamp, aggregateData, aggTidData);
        if (write_flame_graph_) {
            // fprintf(collect_file_, "%s\n", aggregateData->ToString().c_str());  // Write To File.
            // resetLogFile();
        } else {
            aggregateData->ToString();
        }
    }

    // fprintf(stdout, "Before Exipre Size: %d\n", sample_datas_->size());
    // Expire RingBuffer Datas.
    sample_datas_->expire(timestamp - flame_graph_ctx.cache_keep_time_);
    // fprintf(stdout, "After Exipre Size: %d\n", sample_datas_->size());
    last_collect_time_ = timestamp;
}

string FlameGraph::GetOnCpuData(__u32 tid, vector<std::pair<uint64_t, uint64_t>> &periods) {
    AggregateData *aggregateData = new AggregateData(tid);

    __u64 start_time = 0, end_time = 0;
    int size = periods.size();
    for (int i = 0; i < size; i++) {
        start_time = periods[i].first / 1000000; // ns->ms
        end_time = periods[i].second / 1000000; // ns->ms
        if (start_time < end_time) {
            // fprintf(stdout, ">> Collect: %lld -> %lld, Duration: %lld\n", start_time, end_time, end_time-start_time);
            sample_datas_->collect(start_time, end_time, aggregateData, aggTidData);
        }
    }
    return aggregateData->ToString();
}

void FlameGraph::resetLogFile() {
    char collectFileName[128];
    time_t nowtime = time(NULL);
    tm *now = localtime(&nowtime);
    snprintf(collectFileName, sizeof(collectFileName), "flamegraph_%d_%d_%d.txt", now->tm_hour, now->tm_min, now->tm_sec);
    collect_file_ = fopen(collectFileName, "w+");
}
