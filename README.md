# syscall_top
Este software permite visualizar las syscalls ejecutadas por cada proceso en tiempo real. Además, permite la configuración de reglas, por ejemplo, matar al proceso que supera cierta cantidad de syscalls. Se puede utilizar este módulo para la detección en tiempo real de Ransomwares.

Por ahora, no se recomienda utilizar este software en ambientes de producción.

# Reglas
Las reglas deben especificarse en el archivo `rules.ini` y deben seguir la siguiente especificación:
```
[SIGNAL]
syscall=threshold/<seconds>

[SUBSCRIBERS-SYSUSR1]
read=10000
write=10000
password=<password>

[SPECIAL_SETTINGS]
ram_backup=100M
hard_disk_backup=100M
```

# Requisitos
- Kernel 4.4  
- make  
- gcc  

# Para compilar e instalar el módulo del kernel.
Posicionarte en la raíz para compilar el módulo:  
`$ make`

Instalar el módulo del kernel con:
`$ sudo insmod syscall_top.ko`

Crear el archivo de caracteres o dispositivo de caracteres con:
`$ sudo mknod /dev/syscall_top c 246 0`

Cambiar el propietario del dispositivo:
`$ sudo chown [TU_USUARIO] /dev/syscall_top`


# Para chequear que se instaló correctamente
`$ sudo lsmod | grep syscall_top`


# Para ejecuctar el frontend
`$ cd frontend`
`$ python3 syscall_top.py`


# Tabla de syscalls
https://filippo.io/linux-syscall-table/


# Proyecto relacionados
Primera versión del detector de ransomware: https://github.com/LabSis/detector-ransomware
Contador de syscalls con strace: https://github.com/LabSis/contador_syscalls

# Contribuir
Si querés contribuir, sólo hazlo. ¡Muchas gracias!
