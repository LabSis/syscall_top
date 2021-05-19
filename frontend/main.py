import struct
import psutil

processes_from_psutil = []


def generate_processes_list():
    psutil.process_iter(attrs=None, ad_value=None)
    
    # Itero por los procesos reales y los mapeo adentro de la estructura.
    for proc in psutil.process_iter():
        try:
            process_name = proc.name()
            process_id = proc.pid
            processes_from_psutil.append((process_id, process_name))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
           pass


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
        read_count = 0
        write_count = 0
        open_count = 0
        close_count = 0
        for syscall in self.syscalls:
            syscall_index = syscall[0]
            if syscall_index == 0:
                read_count += 1
            if syscall_index == 0:
                write_count += 1
            if syscall_index == 0:
                open_count += 1
            if syscall_index == 0:
                close_count += 1
            total_count += syscall[1]
            
        return "%d\t%d\t%d\t%d\t%d\t%d\t%s" % (self.pid, read_count, write_count, 
                                            open_count, close_count,
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

    print("PID\tread\twrite\topen\tclose\ttotal\tname")
    print("=" * 80)
    for pid in processes:
        process = processes[pid]
        print("%s" % str(process))


if __name__ == "__main__":
    #generate_processes_list()
    read_syscalls_count()

