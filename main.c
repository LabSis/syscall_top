#include <stdio.h>

#define PIDS 500
#define SYSCALLS 400

int pids[PIDS];
int syscall_x_pids[PIDS][SYSCALLS];

void init_data_structures() {
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

void intercept(int pid, int syscall_id) {
    int empty_index = -1;
    int pid_index = search(pids, pid); // O(N)
    if (pid_index > -1){
        //  Existe el pid en nuestra estructura de datos y por lo tanto está vivo.
        syscall_x_pids[pid_index][syscall_id] += 1;
    } else {
        // No existe en nuestra estructura de datos.
        empty_index = search(pids, -1);
        if (empty_index <= -1) {
            // No hay espacio para guardar más procesos.
            printf("No tenemos más espacio");
        } else {
            // Hay espacio y hay que guardarlo.
            pids[empty_index] = pid;
            for (int i = 0; i < SYSCALLS; i++) {
                syscall_x_pids[empty_index][i] = 0;
            }
            syscall_x_pids[empty_index][syscall_id] = 1;
	}
    }
}

void kill(int pid) {
    // Asumiendo que el proceso se esta por matar.

    // Limpiar la estructura de datos.
    int pid_index = search(pids, pid);
    if (pid_index > -1) {
        pids[pid_index] = -1;
        for (int i = 0; i < SYSCALLS; i++) {
            syscall_x_pids[pid_index][i] = 0;
        }
    } else {
        // Es la primera syscall que se ejecuta de este proceso, ignoramos...
    }
}

void print_data_structures() {
    int i;
    int j;
    for (i = 0; i < PIDS; i++) {
        for (j = 0; j < SYSCALLS; j++) {
            if (pids[i] > 0 && syscall_x_pids[i][j] > 0) {
                printf("PID: %d - SYSCALL(%d) = %d\n", pids[i], j, syscall_x_pids[i][j]);
            }
        }
    }
}

int main (void) {
    printf("INICIADO\n");
    init_data_structures();

    // Simulacion de intercepciones
    intercept(902, 12);
    intercept(902, 12);
    intercept(903, 12);
    intercept(903, 12);
    intercept(902, 13);
    kill(902);
    intercept(904, 1);
    intercept(905, 100);
    intercept(903, 12);
    intercept(903, 10);
    intercept(902, 2);

    // Print de la estructura de datos
    print_data_structures();
    printf("FINALIZADO\n");
}

