# syscall_top

Este software es un módulo del kernel que intercepta syscalls y permite contabilizarlas. Además, viene acompañado de otro software para poder visualzar estos datos.

Todavía no compila.

# Enlaces de utilidad
https://filippo.io/linux-syscall-table/

# Comandos utilizados
strace -f -c -S calls find /

# Tareas a hacer
1. Mejorar el algoritmo de print_data_structures.  
2. Poder enviar los datos al espacio de usuario.  
3. Poder limpiar el contador de espacio de usuario.  
4. Agregar las 313 syscalls.  
5. Mostrar tamaño completo.  
6. Interceptar kill para guardar los datos de ese proceso en una tabla temporal.  
7. Averiguar las syscalls más utilizadas a través de strace.  
