#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */
#include <linux/sched.h>
#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */

#include "detector.h"

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256
#define PIDS 500
#define SYSCALLS 400

int pids[PIDS];
int syscall_x_pids[PIDS][SYSCALLS];

unsigned long *syscall_table = NULL;

asmlinkage long (*original_ptrace)(int request, pid_t pid, void *addr, void *data);
asmlinkage int (*original_close)(int fd);
asmlinkage int (*original_fstat)(int fd, struct stat *buf);
asmlinkage int (*original_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
asmlinkage int (*original_stat)(const char __user *filename, struct stat __user *statbuf);
asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int (*original_read)(int fd, void *buf, size_t count);


static void init_data_structures(void) {
    int i;
    int j;
    for (i = 0; i < PIDS; i++) {
        pids[i] = -1;
        for (j = 0; j < SYSCALLS; j++) {
            syscall_x_pids[i][j] = 0;
        }
    }
}

int search(int* pids, int pid) {
    int i;
    for (i = 0; i < PIDS; i++) {
        if (pids[i] == pid) {
            return i;
        }
    }
    return -1;
}


static void print_data_structures(void) {
    int i;
    int j;
    for (i = 0; i < PIDS; i++) {
        for (j = 0; j < SYSCALLS; j++) {
            if (pids[i] > 0 && syscall_x_pids[i][j] > 0) {
                printk("PID: %d - SYSCALL(%d) = %d\n", pids[i], j, syscall_x_pids[i][j]);
            }
        }
    }
}

static int find_sys_call_table (char *kern_ver) {
    char system_map_entry[MAX_VERSION_LEN];
    int i = 0;

    /*
     * Holds the /boot/System.map-<version> file name as we build it
     */
    char *filename;

    /*
     * Length of the System.map filename, terminating NULL included
     */
    size_t filename_length = strlen(kern_ver) + strlen(BOOT_PATH) + 1;

    /*
     * This will point to our /boot/System.map-<version> file
     */
    struct file *f = NULL;
 
    mm_segment_t oldfs;
 
    oldfs = get_fs();
    set_fs (KERNEL_DS);

    printk(KERN_INFO "Kernel version: %s\n", kern_ver);
     
    filename = kmalloc(filename_length, GFP_KERNEL);
    if (filename == NULL) {
        printk(KERN_INFO "kmalloc failed on System.map-<version> filename allocation");
        return -1;
    }
     
    /*
     * Zero out memory to be safe
     */
    memset(filename, 0, filename_length);
     
    /*
     * Construct our /boot/System.map-<version> file name
     */
    strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
    strncat(filename, kern_ver, strlen(kern_ver));
     
    /*
     * Open the System.map file for reading
     */
    f = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(f) || (f == NULL)) {
        printk(KERN_INFO "Error opening System.map-<version> file: %s\n", filename);
        return -1;
    }
 
    memset(system_map_entry, 0, MAX_VERSION_LEN);
 
    /*
     * Read one byte at a time from the file until we either max out
     * out our buffer or read an entire line.
     */
    while (vfs_read(f, system_map_entry + i, 1, &f->f_pos) == 1) {
        /*
         * If we've read an entire line or maxed out our buffer,
         * check to see if we've just read the sys_call_table entry.
         */
        if ( system_map_entry[i] == '\n' || i == MAX_VERSION_LEN ) {
            // Reset the "column"/"character" counter for the row
            i = 0;
             
            if (strstr(system_map_entry, "sys_call_table") != NULL) {
                char *sys_string;
                char *system_map_entry_ptr = system_map_entry;
                 
                sys_string = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);  
                if (sys_string == NULL) { 
                    filp_close(f, 0);
                    set_fs(oldfs);

                    kfree(filename);
     
                    return -1;
                }
                memset(sys_string, 0, MAX_VERSION_LEN);
                strncpy(sys_string, strsep(&system_map_entry_ptr, " "), MAX_VERSION_LEN);
                kstrtoul(sys_string, 16, &syscall_table);
                kfree(sys_string);

                break;
            }
            memset(system_map_entry, 0, MAX_VERSION_LEN);
            continue;
        }
        i++;
    }

    filp_close(f, 0);
    set_fs(oldfs);
    kfree(filename);

    return 0;
}

/*
 * We have to pass in a pointer to a buffer to store the parsed
 * version information in. If we declare a pointer to the
 * parsed version info on the stack of this function, the
 * pointer will disappear when the function ends and the
 * stack frame is removed.
 */
char *acquire_kernel_version (char *buf) {
    struct file *proc_version;
    char *kernel_version;
  
    /*
     * We use this to store the userspace perspective of the filesystem
     * so we can switch back to it after we are done reading the file
     * into kernel memory
     */
    mm_segment_t oldfs;
  
    /*
     * Standard trick for reading a file into kernel space
     * This is very bad practice. We're only doing it here because
     * we're malicious and don't give a damn about best practices.
     */
    oldfs = get_fs();
    set_fs (KERNEL_DS);
  
    /*
     * Open the version file in the /proc virtual filesystem
     */
    proc_version = filp_open(PROC_V, O_RDONLY, 0);
    if (IS_ERR(proc_version) || (proc_version == NULL)) {
        return NULL;
    }
  
    /*
     * Zero out memory just to be safe
     */
    memset(buf, 0, MAX_VERSION_LEN);
  
    /*
     * Read version info from /proc virtual filesystem
     */
    vfs_read(proc_version, buf, MAX_VERSION_LEN, &(proc_version->f_pos));
  
    /*
     * Extract the third field from the full version string
     */
    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");
  
    filp_close(proc_version, 0);
    
    /*
     * Switch filesystem context back to user space mode
     */
    set_fs(oldfs);
  
    return kernel_version;
}

void intercept(int pid, int syscall_id) {
    int empty_index = -1;
    int pid_index = search(pids, pid); // O(N)
    int i = 0;
    if (pid_index > -1){
        //  Existe el pid en nuestra estructura de datos y por lo tanto está vivo.
        syscall_x_pids[pid_index][syscall_id] += 1;
    } else {
        // No existe en nuestra estructura de datos.
        empty_index = search(pids, -1);
        if (empty_index <= -1) {
            // No hay espacio para guardar más procesos.
            printk("No tenemos más espacio");
        } else {
            // Hay espacio y hay que guardarlo.
            pids[empty_index] = pid;
            for (i = 0; i < SYSCALLS; i++) {
                syscall_x_pids[empty_index][i] = 0;
            }
            syscall_x_pids[empty_index][syscall_id] = 1;
	    }
    }
}

void updateOtherCounts(int syscall_id){
        int pid = current->pid;
        intercept(pid, syscall_id);
}

asmlinkage long new_ptrace(int request, pid_t pid, void *addr, void *data){
	updateOtherCounts(__NR_ptrace);
	return original_ptrace(request, pid, addr, data);
}

asmlinkage int new_close(int fd){
	updateOtherCounts(__NR_close);
	return original_close(fd);
}

asmlinkage int new_fstat(int fd, struct stat *buf){
	updateOtherCounts(__NR_fstat);
	return original_fstat(fd, buf);
}

asmlinkage int new_openat(int dirfd, const char *pathname, int flags, mode_t mode){
    updateOtherCounts(__NR_openat);
	return original_openat(dirfd, pathname, flags, mode);
}

asmlinkage int new_stat (const char __user * filename, struct stat __user * statbuf) {
	updateOtherCounts(__NR_stat);
	return original_stat(filename, statbuf);
}

asmlinkage int new_write (unsigned int fd, const char __user *bytes, size_t size) {
    updateOtherCounts(__NR_write);
	return original_write(fd, bytes, size);
}

asmlinkage int new_read(int fd, void *buf, size_t count) {
    updateOtherCounts(__NR_read);
	return original_read(fd, buf, count);
}

static int __init onload(void) {
    int i = 0;

    char *kernel_version = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);

    find_sys_call_table(acquire_kernel_version(kernel_version));

    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));

        original_ptrace = (void *)syscall_table[__NR_ptrace];
        syscall_table[__NR_ptrace] = (unsigned long) &new_ptrace;

        original_close = (void *)syscall_table[__NR_close];
        syscall_table[__NR_close] = (long) &new_close;

        original_fstat = (void *)syscall_table[__NR_fstat];
        syscall_table[__NR_fstat] = (long) &new_fstat;

        original_openat = (void *)syscall_table[__NR_openat];
        syscall_table[__NR_openat] = (long) &new_openat;

        original_stat = (void *)syscall_table[__NR_stat];
        syscall_table[__NR_stat] = (long) &new_stat;

        original_write = (void *)syscall_table[__NR_write];
        syscall_table[__NR_write] = (long) &new_write;

        original_read = (void *)syscall_table[__NR_read];
        syscall_table[__NR_read] = (long) &new_read;

        write_cr0 (read_cr0 () | 0x10000);
        printk(KERN_INFO "Syscall top iniciado\n");
    } else {
        printk(KERN_INFO "Error al detectar la syscall table\n");
    }

    kfree(kernel_version);

    /*
     * A non 0 return means init_module failed; module can't be loaded.
     */
    return 0;
}

static void __exit onunload(void) {
	printk(KERN_INFO "Descargando\n");
    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));
        printk(KERN_INFO "Modo no protegido\n");
        //print_data_structures();
        syscall_table[__NR_ptrace] = (long) original_ptrace;
        syscall_table[__NR_close] = (long) original_close;
        syscall_table[__NR_fstat] = (long) original_fstat;
        syscall_table[__NR_openat] = (long) original_openat;
        syscall_table[__NR_stat] = (long) original_stat;
        syscall_table[__NR_write] = (long) original_write;
        syscall_table[__NR_read] = (long) original_read;
        write_cr0 (read_cr0 () | 0x10000);
        printk(KERN_INFO "Syscall top desactivado\n");
    } else {
        printk(KERN_INFO "Error al desactivar el syscall top\n");
    }
}

module_init(onload);
module_exit(onunload);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("UTN FRC LabSis");
MODULE_DESCRIPTION("Detector ransomware");
