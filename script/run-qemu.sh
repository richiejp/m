#!/bin/sh -eu

arch=$1
initrd=$2
kernel=$3

shift 3

Q=qemu-system

case $arch in
        arm64|aarch64) \
                $Q-aarch64 -m 4G \
                           -smp 4 \
                           -display none \
                           -machine virt -cpu cortex-a57 \
		           -nodefaults \
		           -device virtio-rng-pci \
                           -kernel $kernel \
                           -initrd $initrd \
                           -serial stdio \
                           -append 'console=ttyAMA0 earlyprintk=ttyAMA0' \
                           $@;;
        kvm) \
                qemu-kvm -m 4G \
                         -smp 4 \
                         -cpu host \
                         -display none \
		         -nodefaults \
		         -device virtio-rng-pci \
                         -kernel $kernel \
                         -initrd $initrd \
                         -serial stdio \
                         -fsdev local,readonly,security_model=mapped,id=fsdev-fs0,path=$(realpath .) \
                         -device virtio-9p-pci,fsdev=fsdev-fs0,mount_tag=fs0 \
                         -append 'console=ttyS0 earlyprintk=ttyS0 nokaslr panic=0' \
                         $@;;
        *) echo "Don't recognise $arch"
           exit 1;;
esac

# slub_debug=T,kmalloc-512
