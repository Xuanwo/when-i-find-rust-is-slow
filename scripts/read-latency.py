# Please install bcc and bcc-python first
from bcc import BPF
import time
import argparse

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

BPF_HASH(fd_info, pid_t, int);
BPF_HASH(action_info, pid_t, u64);

struct event_data_t {
    u32 pid;
    u64 delta_ts;
};


BPF_RINGBUF_OUTPUT(events, 65536);

static __always_inline int matchPrefix(const char *cs, const char *ct, int size) {
    int len = 0;
    unsigned char c1, c2;
    for (len=0;len<(size & 0xff);len++) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2) return c1 < c2 ? -1 : 1;
        if (!c1) break;
     }
     return 0;
}

int trace_openat_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    if (matchPrefix(filename, "/tmp/demofile2", sizeof(filename)) != 0) {
        return 0;
    }
    fd_info.update(&tid, &dfd);

    return 0;
}

int trace_openat_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    int *dfd = fd_info.lookup(&tid);
    if (dfd == NULL) {
        return 0;
    }
    int ret = PT_REGS_RC(ctx);
    fd_info.update(&tid, &ret);
    return 0;
}

int trace_read_entry(struct pt_regs *ctx, int fd, char __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    int *dfd = fd_info.lookup(&tid);
    if (dfd == NULL) {
        return 0;
    }

    if (*dfd != fd) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    action_info.update(&tid, &ts);

    return 0;
}

int trace_read_return(struct pt_regs *ctx, int ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    u64 *ts = action_info.lookup(&tid);
    if (ts == NULL) {
        return 0;
    }
    action_info.delete(&tid);
    struct event_data_t *event_data = events.ringbuf_reserve(sizeof(struct event_data_t));
    if (!event_data) {
        return 0;
    }
    event_data->pid = pid;
    event_data->delta_ts = bpf_ktime_get_ns() - *ts;
    events.ringbuf_submit(event_data, sizeof(event_data));
    return 0;
}
"""

bpf = BPF(text=bpf_text)

bpf.attach_kprobe(event="do_sys_openat2", fn_name="trace_openat_entry")
bpf.attach_kretprobe(event="do_sys_openat2", fn_name="trace_openat_return")
bpf.attach_kprobe(event="ksys_read", fn_name="trace_read_entry")
bpf.attach_kretprobe(event="ksys_read", fn_name="trace_read_return")

def process_event_data(cpu, data, size):
    event = bpf["events"].event(data)
    print(f"Process {event.pid} read file {event.delta_ts} ns")


bpf["events"].open_ring_buffer(process_event_data)

while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
