import struct

f = open("/dev/syscall_top", "rb")
#data = f.read()

#data = struct.unpack('i', f.read(4))

#int_data = [x for x in data]

values = struct.iter_unpack("i", f.read())

int_data = []
for v in values:
    int_data.append(v[0])

for value in range(0, len(int_data), 3):
    pid = int_data[value]
    syscall_index = -1
    count = -1
    if value + 1 < len(int_data):
        syscall_index = int_data[value + 1]
    if value + 2 < len(int_data):
        count = int_data[value + 2]
    print(pid, syscall_index, count)


