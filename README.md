# About

This shows how to create a small Linux VM with a Zig program running
as init. I'm using it to test the kernel.

Presently the init performs a `switch_root` onto a `tmpfs` root and
mounts `/proc` and `/sys`. Then it hands off to Busybox to run some
more setup and start a shell.

Below is what the output looks like with `-Doptimize=ReleaseSafe`.

```sh
...
[    0.361427] Run /init as init process
info: Zig is running as init!
info: uname: Linux localhost 6.1.42 #5 SMP PREEMPT_DYNAMIC Thu Aug  3 11:36:24 BST 2023 x86_64 (none)
info: Switching root away from rootfs because of pivot_root
info: Temporarily mounted new root at /newroot
info: Moved root contents to /newroot
info: Moved /newroot to /
info: chrooted into new /
info: Mounting /proc and /sys, we'll get proper error traces now
/bin/sh: can't access tty; job control turned off
~ #
```

The kernel creates an initial file system called rootfs and populates
it with the contents of the initrd image. This is basically a tmpfs
file system and would be fine for testing except that it does not
support `pivot_root`. So we make a new root fs.

Related article: [Minimal Linux VM cross compiled with Clang and Zig](zig-cross-compile-ltp-ltx-linux)

# Build

This covers building a complete Linux VM with our Zig userland. We
build two images, a kernel and initrd, which can be "direct booted" by
QEMU.

For now it doesn't cover building Busybox. I haven't figured out how
to do that with Zig yet.

## Nix note

If you are using Nix and have flakes enabled then you can do:

```sh
$ nix develop
```

This will provide an unstable Zig (with ZLS), Busybox and bunch of
stuff for kernel development. However note that Nix's `lld.ld` wrapper
script has an issue with kernel compilation. There is a workaround
listed below.

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

Create the directory tree and copy in our init, for example:

```sh
$ mkdir -p initrds/x86_64/bin
$ cp zig-out/bin/m initrds/x86_64/init
```

If you have Busybox on your host system then you can copy it in with
the following:

```sh
$ script/add-dyn-exe.sh initrds/x86_64 busybox
$ script/link-busybox.sh initrds/x86_64 busybox
```

You *may* need to include kernel modules in your initrd:

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

# TODO

A big motivator for doing this is to leverage Zig's cross compilation
abilities and build system. So obviously I want Zig to compile Busybox
and whatever else.

I also want to reduce the amount of shell script to minimum. `zig
build <subcmd>` should replace the scripts on the host and init will
replace `/etc/init.d/rcS`.

# Acknowledgments

- Thanks jacobly helping me with why debug symbols were missing.
