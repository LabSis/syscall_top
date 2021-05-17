#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>

#define DEVICE "/dev/syscall_top"

int fd = 0;
int ppos = 0;

int read_stat()
{
    int read_length = 256;
    ssize_t ret;
    int *data = (int *) malloc(1024 * sizeof(int));
    memset(data, 0, sizeof(data));
    data[0] = '\0';
    ret = read(fd, data, read_length, &ppos);
    if (ret == -1) {
        return -1;
    }
    while (ret > 0) {
        ret = read(fd, data, read_length, &ppos);
        if (ret == 0) {
            break;
        }
        printf ("%zd\n", ret);
        ppos += read_length;
        if (ret == -1) {
            return -1;
        }
        for (int i = 0; i < read_length / 4; i += 3) {
            printf("PID(%i) - Syscall(%i) = %i\n", data[i], data[i + 1], data[i + 2]);
            fflush(stdout);
        }
    }
    for (int i = 0; i < read_length / 4; i += 3) {
        printf("PID(%i) - Syscall(%i) = %i\n", data[i], data[i + 1], data[i + 2]);
        fflush(stdout);
    }
    fflush(stdout);
    free(data);
    return 0;
}

int main()
{
    int value = 0;
    if (access(DEVICE, F_OK) == -1) {
        printf("module %s not loaded\n", DEVICE);
        return 0;
    } else {
        printf("module %s loaded, will be used\n", DEVICE);
    }
    
    printf("Press to read stat");
    scanf("%d", &value);
    fd = open(DEVICE, O_RDWR);
    int ret = read_stat();
    if (ret == -1) {
        printf("Error al conectarse con el driver");
    }
    close(fd);

    return 0;
}
