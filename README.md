# Build

This covers building a complete Linux VM with our Zig userland. We
build two images, a kernel and initrd, which can be "direct booted" by
QEMU.

## Nix note

If you are using Nix and have flakes enabled then you can do:

```sh
$ nix develop
```

This will provide an unstable Zig (with ZLS) and bunch of stuff for
kernel development. However note that Nix's `lld.ld` wrapper script
has an issue with kernel compilation. There is a workaround listed
below.

## Init

Run `zig build` or `zig build -Dtarget=aarch64-linux-none` to cross
compile.

## Kernel

The Linux kernel can be cross compiled with LLVM in the following way.

```sh
$ cd $linux_git_checkout
$ make LLVM=1 ARCH=arm64 defconfig
$ make LLVM=1 ARCH=arm64 menuconfig # Optional
$ make LLVM=1 ARCH=arm64 -j$(nproc)
```

Or just remove `ARCH` if you are not cross compiling. In that case you
can also drop `LLVM` and use the GNU toolchain. If you are using Nix
then you have to specify `gcc` as the host compiler to avoid linker
errors.

```sh
$ make HOSTCC=gcc CC=clang LLVM=1 ...
```

We need the `Image.gz` file on ARM64, other architectures use
different names. For example on x86 it is `bzImage`.

```sh
$ mkdir -p $m_git_checkout/kernels/arm64
$ cp arch/arm64/boot/Image.gz $m_git_checkout/kernels/arm64/Image.gz
```

## Initrd

Create the directory tree, for example:

```sh
$ mkdir -p initrds/x86_64/bin
$ cp zig-out/bin/m initrds/x86_64/init
```

You may need to include kernel modules in your initrd:

```sh
$ cd $linux_git_checout
$ INSTALL_MOD_PATH=$m_git_checkout/initrds/x86_64 make modules_install
```

Create the `cpio` archive

```sh
$ cd $m_git_checkout
$ scripts/mk-initrd.sh
```

# Run

If you built a x86_64 kernel on x86_64 then do

```sh
$ script/run-qemu.sh kvm initrds/x86_64.cpio.gz kernels/x86_64/bzImage
```

If you cross compiled arm64 then its

```sh
$ script/run-qemu.sh arm64 initrds/arm64.cpio.gz kernels/arm64/Image.gz
```
