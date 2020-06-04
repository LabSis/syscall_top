PIDS = 500
SYSCALLS = 400
int pids[PIDS] = [10, 40, 104, 506];
int syscall_x_pids[PIDS][SYSCALLS] = COUNT

function init_data_structures() {
	pids = new int[PIDS];
	syscall_x_pids = new int[PIDS]
	for (int i = 0; i < PIDS; i++) {
		pids[i] = -1;
		syscall_x_pids[i] = null;
	}
}

function intercept() {
	pid = 506
	syscall_id = 2 // syscall_id == syscall_index
	pid_index = search(pids, pid) // O(N)
	if (pid_index > -1){
		//  Existe el pid en nuestra estructura de datos y por lo tanto está vivo.
		syscall_x_pids[pid_index][syscall_id] += 1

	} else {
		// No existe en nuestra estructura de datos.
		// Hay que agregarlo al pid.
		empty_index = search_empty(pids)
		if (empty_index <= -1) {
			// No hay espacio para guardar más procesos.
			printk(“No tenemos más espacio”);
		} else {
			// Hay espacio y hay que guardarlo.
			pids[empty_index] = pid;
			syscall_x_pids[empty_index] = new int[SYSCALLS];
			for (int i = 0; i < SYSCALLS; i++) {
				syscall_x_pids[empty_index][i] = 0;
			}
			syscall_x_pids[empty_index][syscall_id] = 1
		}
	}
}

kill(pid, señal) {
	valor = kill_original(pid, señal);

	bool ok = false;
	for_each_process(task_list) {
		if (pid == task_list->pid) {
			// ESTA VIVO
			ok = true;
		}
	}
	if (ok) {
		// Limpiar la estructura del pid.
		pid_index = search(pids, pid)
		if (pid_index > -1) {
			pids[pid_index] = -1;
			if (syscall_x_pids[pid_index] != null) {
				free(syscall_x_pids[pid_index]);
				syscall_x_pids[pid_index] = null;
			}
		} else {
			// Es la primera syscall que se ejecuta de este proceso, ignoramos...
		}
	}
}



