#!/usr/bin/python3
import struct
import psutil
from curses import wrapper
import time
import threading
import sys
import re
import configparser

write_kill = None
read_kill = None
write_stop = None
read_stop = None
pattern = None

def show_data(stdscr, processes):
    stdscr.clear()
    stdscr.addstr(0, 0, "SyscallTop")
    stdscr.addstr(1, 0, "PID\tread\twrite\topen\tclose\tother\ttotal\tname")
    stdscr.addstr(2, 0, "=" * 80)
    height, width = stdscr.getmaxyx()
    i = 3
    position = i
    for pid in processes:
        process = processes[pid]
        process_name = str(process)
        
        # TODO: Establecer bien el ancho máximo.
        process_name = process_name[:width - 1]
        show_process = True
        if pattern is not None and pattern != "":
            show_process = bool(re.match(".*" + pattern + ".*", process_name))
        if show_process:
            if position < height:
                stdscr.addstr(position, 0, process_name)
                position += 1
            else:
                break
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
        self.read_count = 0
        self.write_count = 0
        self.timelive = 0

    def __str__(self):
        total_count = 0
        other_count = 0
        read_count = 0
        write_count = 0
        open_count = 0
        close_count = 0
        max_count = 0
        index_max_count = -1
        for syscall in self.syscalls:
            syscall_index = syscall[0]
            if syscall_index == 0:
                read_count = syscall[1]
            if syscall_index == 1:
                write_count = syscall[1]
            if syscall_index == 2:
                open_count = syscall[1]
            if syscall_index == 3:
                close_count = syscall[1]
            if syscall[1] > max_count:
                max_count = syscall[1]
                index_max_count = syscall[0]
            total_count += syscall[1]
        other_count = total_count - read_count - write_count - open_count - close_count
        self.write_count = write_count
        self.read_count = read_count
        return "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s(%d)" % (self.pid, read_count, write_count, 
                                            open_count, close_count, other_count,
                                            total_count, self.name, index_max_count)


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
            if process_name == "Unknown" or process_name == "syscall_top.py":
                continue
            if pid in processes:
                process = processes[pid]
                process.syscalls.append((syscall_index, count))
            else:
                process = Process(pid, process_name, [(syscall_index, count)])
                processes[pid] = process
    f.close()
    return processes

def apply_rules(processes):
    for pid in processes:
        process = processes[pid]
        read_count = process.read_count
        write_count = process.write_count
        
        if write_kill is not None and read_kill is not None:
            if write_count > write_kill and read_count > read_kill:
                f = open("/dev/syscall_top", "w")
                f.write(str(pid))
                f.close()

        if write_stop is not None and read_stop is not None:
            if write_count > write_stop and read_count > read_stop:
                f = open("/dev/syscall_top", "w")
                f.write(str(pid))
                f.close()

def task(stdscr):
    while True:
        processes = read_syscalls_count()
        show_data(stdscr, processes)
        apply_rules(processes)
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

def read_rule(read_config, section, option):
    try:
        return int(read_config.get(section, option))
    except:
        return None

def read_rules():
    global write_kill, read_kill, write_stop, read_stop
    read_config = configparser.ConfigParser()
    read_config.read("rules.ini")
    
    write_kill = read_rule(read_config, "SIGKILL", "write")
    read_kill = read_rule(read_config, "SIGKILL", "read")
    write_stop = read_rule(read_config, "SIGSTOP", "write")
    read_stop = read_rule(read_config, "SIGSTOP", "read")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        pattern = sys.argv[1]
    read_rules()
    wrapper(main)
