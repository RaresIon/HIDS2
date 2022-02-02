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
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 syscallNo;
};

BPF_PERF_OUTPUT(events);

int clone(struct pt_regs *ctx) {
    struct data_t data = {};

    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int mmap(struct pt_regs *ctx) {
    struct data_t data = {};

    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int execve(struct pt_regs *ctx) {
    struct data_t data = {};

    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=2;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int read(struct pt_regs *ctx) {
    struct data_t data = {};

    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=3;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int write(struct pt_regs *ctx) {
    struct data_t data = {};

    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=4;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""



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
# file = open('benchmarkData.csv','w')
# writer = csv.writer(file)
print("file opened")    
comm_list = []
command_dict = {}
lastSyscall = ''
def print_event(cpu, data, size):
    global start 
    global iteration 
    global prevtime
    global elapsed_iter
    global writer
    global comm_list
    global command_dict
    
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
    # if start == 0:
    #         start = event.ts
    # time_s = (float(event.ts - start)) / 1000000000
      # if lastSyscall != syscallNo:
    if command_dict.get(event.pid,0) < 50:
        command_dict[event.pid] = command_dict.get(event.pid, 0) + 1
        print("%-6d %-16s %-6d %-6d %s %-6d" % (event.uid, event.comm, command_dict.get(event.pid, 0), event.pid,
             syscallNo, len(command_dict)))
    
        
        # comm_list.append(event.comm)
        # print(comm_list)
    # if event.comm != "code":
    #     print("%-6d %-16s %-6d %s" % (event.uid, event.comm, event.pid,
    #         syscallNo))
    # mycursor.execute("""INSERT INTO 
    #                syscalls 
    #                (PID, syscall_name) 
    #            VALUES
    #                (%(PID)s, %(syscall_name)s)""", 
    #         { 
    #          'PID': event.pid, 
    #          'syscall_name': syscallNo  }) 
     #       lastSyscall = syscallNo
    # if(time_s - prevtime > 0.8):
    #     append_or_add_to_dict(event.pid,syscallNo,time_s,event.comm)
    #     prevtime = time_s
    #     print("########START############")
    #     print(datadict)
    #     print("########END############")
    #writer.writerow([iteration, time_s, event.comm, event.pid, syscallNo ])
    # if event.comm != "python3" and  event.comm != "code":
    #     iteration = iteration + 1
    #     writer.writerow([iteration,time_s,event.comm,event.pid, syscallNo])
    #     if iteration >= 1000000:
    #         writer.writerow([iteration,time_s,event.comm,event.pid, syscallNo])
    #         file.close()
    #         sys.exit(0)    
    


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
   