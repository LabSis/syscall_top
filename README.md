# syscall_top

Este software es un módulo del kernel que intercepta syscalls y permite contabilizarlas. Además, viene acompañado de otro software para poder visualzar estos datos.

# Para instalar

make
sudo insmod detector.ko
dmesg
// Y ejecutar el comando mknod que sale en dmesg

# Para chequear que se instaló correctamente
sudo lsmod | grep detector

# Para ejecuctar el front
cd frontend
python3 main.py

# Enlaces de utilidad
https://filippo.io/linux-syscall-table/

# Comandos utilizados
strace -f -c -S calls find /
