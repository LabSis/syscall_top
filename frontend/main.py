import struct

class Process():
    def __init__(self, pid, name, syscalls):
        self.pid = pid
        self.name = name
        self.syscalls = syscalls

    def __str__(self):
        total_count = 0
        for syscall in self.syscalls:
            total_count += syscall[1]
        return "%d\t%s\t%d" % (self.pid, self.name, total_count)


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
            if pid in processes:
                process = processes[pid]
                process.syscalls.append((syscall_index, count))
            else:
                process = Process(pid, "Unknown", [(syscall_index, count)])
                processes[pid] = process

    for pid in processes:
        process = processes[pid]
        print("%s" % str(process))

if __name__ == "__main__":
    read_syscalls_count()

