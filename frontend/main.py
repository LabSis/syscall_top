#!/usr/bin/python3
import struct
import psutil
from curses import wrapper
import time
import threading

processes_from_psutil = []


def show_data(stdscr, processes):
    stdscr.clear()
    stdscr.addstr(0, 0, "SyscallTop")
    stdscr.addstr(1, 0, "PID\tread\twrite\topen\tclose\tother\ttotal\tname")
    stdscr.addstr(2, 0, "=" * 80)
    i = 3
    for pid in processes:
        process = processes[pid]
        stdscr.addstr(i, 0, "%s" % str(process))
        i += 1
    stdscr.refresh()


def get_process_name_from_pid(pid_to_search):
    try:
        process_pid = psutil.Process(pid_to_search)
        if process_pid is not None:
            return process_pid.name()
        return "Unknown"
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"


class Process():

    def __init__(self, pid, name, syscalls):
        self.pid = pid
        self.name = name
        self.syscalls = syscalls

    def __str__(self):
        total_count = 0
        other_count = 0
        read_count = 0
        write_count = 0
        open_count = 0
        close_count = 0
        max_count = 0
        for syscall in self.syscalls:
            syscall_index = syscall[0]
            if syscall_index == 0:
                read_count += syscall[1]
            if syscall_index == 1:
                write_count += syscall[1]
            if syscall_index == 2:
                open_count += syscall[1]
            if syscall_index == 3:
                close_count += syscall[1]
            total_count += syscall[1]
        other_count = total_count - read_count - write_count - open_count - close_count
        return "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s" % (self.pid, read_count, write_count, 
                                            open_count, close_count, other_count,
                                            total_count, self.name)


def read_syscalls_count():
    f = open("/dev/syscall_top", "rb")
    values = struct.iter_unpack("i", f.read())

    int_data = []
    for v in values:
        int_data.append(v[0])

    processes = {}
    for value in range(0, len(int_data), 3):
        pid = int_data[value]
        syscall_index = -1
        count = -1
        if value + 1 < len(int_data):
            syscall_index = int_data[value + 1]
        if value + 2 < len(int_data):
            count = int_data[value + 2]
        if pid is not None:
            process_name = get_process_name_from_pid(pid)
            if process_name == "Unknown":
                continue
            if pid in processes:
                process = processes[pid]
                process.syscalls.append((syscall_index, count))
            else:
                process = Process(pid, process_name, [(syscall_index, count)])
                processes[pid] = process
    f.close()
    return processes

def task(stdscr):
    while True:
        processes = read_syscalls_count()
        show_data(stdscr, processes)
        time.sleep(2)

def main(stdscr):
    stdscr.clear()
    
    t = threading.Thread(target=task, args=(stdscr,))
    t.daemon = True
    t.start()

    time.sleep(1)

    while True:
        c = stdscr.getch()
        if c == ord("q"):
            break

if __name__ == "__main__":
    wrapper(main)
