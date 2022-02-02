from time import process_time
from bcc import BPF
import os
import sys
import signal
from threading import Timer
import timeit
import datetime
def run(db_connection, time):
    endTime = datetime.datetime.now() + datetime.timedelta(seconds=5)
    print("SESNOR PID: " ,os.getpid())

    BPF_PROGRAM = r"""
    #include <linux/sched.h>
    struct data_t {
        u32 pid;
        u32 uid;
        char comm[TASK_COMM_LEN];
        u32 syscallNo;
    };

    BPF_PERF_OUTPUT(events);


    int read(struct pt_regs *ctx) {
        struct data_t data = {};

        // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=182;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int write(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=306;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int open(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=163;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

     int creat(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=26;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }


    int lseek(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=124;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int mmap(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=139;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int dup(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=28;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int link(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=117;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int unlink(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=293;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int fstatfs(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=262;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int access(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
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
    int chmod(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=16;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int chown(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=17;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int fork(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=69;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    //int exit(struct pt_regs *ctx) {
    //    struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
      //  data.pid = bpf_get_current_pid_tgid() >> 32;
       // #ifdef FILTER_PID
       // if (data.pid == FILTER_PID)
        //    return 0;
       // #endif
       // data.syscallNo=39;
       // bpf_get_current_comm(&data.comm, sizeof(data.comm));

       // events.perf_submit(ctx, &data, sizeof(data));

       // return 0;
    //}
    int wait4(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=304;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int getuid(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=97;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int getgid(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=79;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int getegid(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=77;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int geteuid(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=78;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int getpid(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=85;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
     int getppid(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=86;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int kill(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=114;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int alarm(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=8;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int chdir(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=15;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int pipe(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=168;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int msgget(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=152;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int msgsnd(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=154;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int msgrcv(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=153;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int semget(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=219;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int semop(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=220;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int shmget(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=252;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    int shmat(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=249;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    int shmdt(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=251;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
      int munmap(struct pt_regs *ctx) {
        struct data_t data = {};

       // data.uid = bpf_get_current_uid_gid();
        // if (data.uid != 0)
        //     return 0;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        #ifdef FILTER_PID
        if (data.pid == FILTER_PID)
            return 0;
        #endif
        data.syscallNo=158;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }  

    """

    BPF_PROGRAM = ("#define FILTER_PID %d\n" % os.getpid()) + BPF_PROGRAM
    bpf = BPF(text=BPF_PROGRAM)
  
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("mmap"), fn_name="mmap")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("read"), fn_name="read")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("write"), fn_name="write")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("open"), fn_name="open")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("creat"), fn_name="creat")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("lseek"), fn_name="lseek")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("dup"), fn_name="dup")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("link"), fn_name="link")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("unlink"), fn_name="unlink")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("fstatfs"), fn_name="fstatfs")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("access"), fn_name="access")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("chmod"), fn_name="chmod")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("chown"), fn_name="chown")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("fork"), fn_name="fork")
    # bpf.attach_kprobe(event=bpf.get_syscall_fnname("exit"), fn_name="exit")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("wait4"), fn_name="wait4")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("geteuid"), fn_name="geteuid")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("getuid"), fn_name="getuid")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("getegid"), fn_name="getegid")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("getgid"), fn_name="getgid")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("getpid"), fn_name="getpid")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("getppid"), fn_name="getppid")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("kill"), fn_name="kill")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("alarm"), fn_name="alarm")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("chdir"), fn_name="chdir")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("pipe"), fn_name="pipe")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("msgget"), fn_name="msgget")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("msgsnd"), fn_name="msgsnd")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("msgrcv"), fn_name="msgrcv")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("semget"), fn_name="semget")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("semop"), fn_name="semop")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("shmget"), fn_name="shmget")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("shmat"), fn_name="shmat")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("shmdt"), fn_name="shmdt")
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("munmap"), fn_name="munmap")
   
   



    
    
    mycursor = db_connection.cursor(buffered = True)            
    mycursor.execute("USE SENSORDB")
    sql = """ insert into TRACES(PID, SYSCALL)values(%s,%s) """
    commit_list = []
    pid_dict = {}
    
    def store_event(cpu, data, size):
        nonlocal sql
        nonlocal commit_list
        nonlocal pid_dict
        event = bpf["events"].event(data)  
        if pid_dict.get(event.pid,0) < 100:
            pid_dict[event.pid] = pid_dict.get(event.pid, 0) + 1
            commit_list.append(tuple((event.pid,event.syscallNo)))
            mycursor.executemany(sql, commit_list)
            if len(commit_list) == 1000:
                try:
                    db_connection.commit()
                except:
                    print("commit failed")
                commit_list = []
                pid_dict = {}
    
    # loop with callback to print_event
    bpf["events"].open_perf_buffer(store_event)
    while True:
        print(datetime.datetime.now())
        try:
            if datetime.datetime.now() >= endTime:
                mycursor.executemany(sql, commit_list)
                db_connection.commit()
                break
            else:    
                bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print('Interrupted')
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)
