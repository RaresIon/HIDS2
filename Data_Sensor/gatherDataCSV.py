from bcc import BPF
import json
import os
import mysql.connector
from mysql.connector import Error
import csv
import sys
import signal

def signal_handler(signal, frame):
    global interrupted
    interrupted = True

signal.signal(signal.SIGINT, signal_handler)


BPF_PROGRAM = r"""
#include <linux/sched.h>
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u32 syscallNo;
};

BPF_PERF_OUTPUT(events);

int clone(struct pt_regs *ctx) {
    struct data_t data = {};

    
    u64 id = bpf_get_current_pid_tgid() ;
    data.pid = id >> 32;

    //return 0 if this pid is filtered
    #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif

    data.ts = bpf_ktime_get_ns();
    data.syscallNo=0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int mmap(struct pt_regs *ctx) {
    struct data_t data = {};

    
    u64 id = bpf_get_current_pid_tgid() ;
    data.pid = id >> 32;

    //return 0 if this pid is filtered
    #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.ts = bpf_ktime_get_ns();
    data.syscallNo=1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int execve(struct pt_regs *ctx) {
    struct data_t data = {};

    
    u64 id = bpf_get_current_pid_tgid() ;
    data.pid = id >> 32;

    //return 0 if this pid is filtered
    #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.ts = bpf_ktime_get_ns();
    data.syscallNo=2;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int read(struct pt_regs *ctx) {
    struct data_t data = {};

    
    u64 id = bpf_get_current_pid_tgid() ;
    data.pid = id >> 32;

    //return 0 if this pid is filtered
    #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif

    data.ts = bpf_ktime_get_ns();
    data.syscallNo=3;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int write(struct pt_regs *ctx) {
    struct data_t data = {};

    u64 id = bpf_get_current_pid_tgid() ;
    data.pid = id >> 32;

    //return 0 if this pid is filtered
    #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif

    data.ts = bpf_ktime_get_ns();
    data.syscallNo=4;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""


BPF_PROGRAM = ("#define FILTER_PID %d\n" % os.getpid()) + BPF_PROGRAM
print("current pid is ",os.getpid())
bpf = BPF(text=BPF_PROGRAM)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("clone"), fn_name="clone")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("mmap"), fn_name="mmap")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="execve")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("read"), fn_name="read")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("write"), fn_name="write")



start = 0
syscallNo = ""
prevsyscall = -1
prevtime = 0

iteration = 0
elapsed_iter = 0
file = open('benchmarkData.csv','w')
writer = csv.writer(file)
print("file opened")    
lastSyscall = ''
def print_event(cpu, data, size):
    global start 
    global iteration 
    global prevtime
    global elapsed_iter
    global writer
    
    event = bpf["events"].event(data)
    if event.syscallNo == 0:
        syscallNo = "clone"
    if event.syscallNo == 1:
        syscallNo = "mmap"
    if event.syscallNo == 2:
        syscallNo = "execve" 
    if event.syscallNo == 3:
        syscallNo = "read" 
    if event.syscallNo == 4:
        syscallNo = "write"                
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000

    # if event.comm != "python" and event.comm != "code" :
    # if lastSyscall != syscallNo:
    #     print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
    #         syscallNo))
    # lastSyscall = syscallNo
    # mycursor.execute("""INSERT INTO 
    #                syscalls 
    #                (PID, syscall_name) 
    #            VALUES
    #                (%(PID)s, %(syscall_name)s)""", 
    #         { 
    #          'PID': event.pid, 
    #          'syscall_name': syscallNo  }) 
    # if(time_s - prevtime > 0.8):
    #     append_or_add_to_dict(event.pid,syscallNo,time_s,event.comm)
    #     prevtime = time_s
    #     print("########START############")
    #     print(datadict)
    #     print("########END############")
    writer.writerow([iteration, time_s, event.comm, event.pid, syscallNo ])
    iteration = iteration + 1
    if iteration >= 1000000:
        writer.writerow([iteration,event.comm,event.pid, syscallNo])
        file.close()
        sys.exit(0)    
    


# loop with callback to print_event
interrupted = False
bpf["events"].open_perf_buffer(print_event)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
   