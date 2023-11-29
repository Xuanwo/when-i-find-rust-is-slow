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

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    char *filename = args->filename;
    if (matchPrefix(filename, "/tmp/file", sizeof(filename)) != 0) {
        return 0;
    }
    int fd=0;
    fd_info.update(&tid, &fd);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    int *dfd = fd_info.lookup(&tid);
    if (dfd == NULL) {
        return 0;
    }
    int fd = args->ret;
    fd_info.update(&tid, &fd);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    int *dfd = fd_info.lookup(&tid);
    if (dfd == NULL) {
        return 0;
    }

    if (*dfd != args->fd) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    action_info.update(&tid, &ts);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
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


def process_event_data(cpu, data, size):
    event = bpf["events"].event(data)
    print(f"Process {event.pid} read file {event.delta_ts} ns")


bpf["events"].open_ring_buffer(process_event_data)

while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
