#!/bin/sh -eu

arch=$1
initrd=$2
kernel=$3

shift 3

Q=qemu-system

case $arch in
        arm64|aarch64) \
                $Q-aarch64 -m 1G \
                           -smp 2 \
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
                qemu-kvm -m 1G \
                         -smp 2 \
                         -cpu host \
                         -display none \
		         -nodefaults \
		         -device virtio-rng-pci \
                         -kernel $kernel \
                         -initrd $initrd \
                         -serial stdio \
                         -append 'console=ttyS0 earlyprintk=ttyS0' \
                         $@;;
        *) echo "Don't recognise $arch"
           exit 1;;
esac
