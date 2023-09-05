const std = @import("std");
const log = std.log;
const fs = std.fs;
const os = std.os;
const errno = os.errno;
const linux = os.linux;
const E = linux.E;
const mem = std.mem;
const Allocator = mem.Allocator;

const MS_MOVE = 8192;

fn mount(
    special: [*:0]const u8,
    dir: [*:0]const u8,
    fstype: [*:0]const u8,
    flags: u32,
    data: usize,
) !void {
    const ret =
        errno(linux.mount(special, dir, fstype, flags, data));

    if (ret == E.SUCCESS)
        return;

    log.err("mount({s}, {s}, {s}, {}, {}) = {}", .{ special, dir, fstype, flags, data, ret });

    return error.mountFailed;
}

fn chroot(path: [*:0]const u8) !void {
    const ret = errno(linux.chroot(path));

    if (ret == E.SUCCESS)
        return;

    return error.chrootFailed;
}

fn ls(path: []const u8) !void {
    var dir = try fs.openDirAbsolute(path, .{});
    var idir = try dir.openIterableDir(path, .{});
    defer idir.close();
    var itr = idir.iterate();

    log.info("ls {s}", .{path});

    while (try itr.next()) |entry| {
        const t = switch (entry.kind) {
            .directory => "dir",
            .file => "file",
            .block_device, .character_device => "dev",
            else => "other",
        };

        log.info("{s:5}: {s}", .{ t, entry.name });
    }
}

fn fstatat(dir: fs.Dir, path: [*:0]const u8, stat_buf: *linux.Stat) !void {
    const ret = errno(linux.fstatat(dir.fd, path, stat_buf, 0));

    if (ret == E.SUCCESS)
        return;

    return error.fstatatFailed;
}

fn mvRec(src: fs.Dir, dst: fs.Dir, root_dev: linux.dev_t) !void {
    var isrc = try src.openIterableDir(".", .{});
    defer isrc.close();
    var itr = isrc.iterateAssumeFirstIteration();

    const dst_stat = try os.fstat(dst.fd);

    while (try itr.next()) |base| {
        switch (base.kind) {
            .file => {
                var src_stat: linux.Stat = undefined;

                try fstatat(src, &try os.toPosixPath(base.name), &src_stat);

                if (src_stat.dev != root_dev) {
                    log.debug("skip file {s}", .{base.name});
                    continue;
                }

                log.debug("mv file {s}", .{base.name});

                try src.copyFile(base.name, dst, base.name, .{});
                try src.deleteFile(base.name);
            },
            .sym_link => {
                log.debug("ln {s}", .{base.name});
                var buf: [linux.PATH_MAX]u8 = undefined;

                const link = try src.readLink(base.name, &buf);
                try dst.symLink(link, base.name, .{});
                try src.deleteFile(base.name);
            },
            .directory => {
                var sub_src = try src.openDir(base.name, .{});
                defer sub_src.close();
                const sub_src_stat = try os.fstat(sub_src.fd);

                log.debug("stat dir {s}: {}", .{ base.name, sub_src_stat });

                if (sub_src_stat.ino == dst_stat.ino) {
                    log.debug("skip dir {s}", .{base.name});
                    continue;
                }

                var sub_dst = try mkpath(dst, base.name, 0o755);
                defer sub_dst.close();

                if (root_dev != sub_src_stat.dev) {
                    log.debug("shallow mv {s}", .{base.name});
                    continue;
                }

                log.debug("mv dir {s}", .{base.name});
                try mvRec(sub_src, sub_dst, root_dev);

                src.deleteDir(base.name) catch |err| {
                    switch (err) {
                        error.DirNotEmpty => {
                            log.debug("left {s}", .{base.name});
                        },
                        else => return err,
                    }
                };
            },
            else => {
                log.debug("skip {} {s}", .{ base.kind, base.name });
            },
        }
    }
}

fn mkpath(dir: fs.Dir, path: []const u8, mode: fs.File.Mode) !fs.Dir {
    var new = try dir.makeOpenPath(path, .{});
    errdefer new.close();

    var inew = try dir.openIterableDir(".", .{});
    defer inew.close();

    try inew.chmod(mode);

    return new;
}

fn switch_root() !void {
    var old_root = try fs.openDirAbsolute("/", .{});
    defer old_root.close();
    const root_dev = (try os.fstat(old_root.fd)).dev;

    {
        var new_root = try mkpath(old_root, "newroot", 0o700);
        defer new_root.close();
        const data: [*:0]const u8 = "size=50%";
        try mount("none", "/newroot", "tmpfs", 0, @intFromPtr(data));
        log.info("Temporarily mounted new root at /newroot", .{});
    }

    var new_root = try old_root.openDir("newroot", .{});
    defer new_root.close();
    try mvRec(old_root, new_root, root_dev);
    log.info("Moved root contents to /newroot", .{});

    try std.os.chdir("/newroot");
    try mount(".", "/", ":-)", MS_MOVE, 0);
    log.info("Moved /newroot to /", .{});

    try chroot(".");
    try std.os.chdir("/");
    log.info("chrooted into new /", .{});
}

fn init() !void {
    log.info("Switching root away from rootfs because of pivot_root", .{});
    try switch_root();

    log.info("Mounting /proc and /sys, we'll get proper error traces now", .{});
    try mount("none", "/proc", "proc", 0, 0);
    try mount("none", "/sys", "sysfs", 0, 0);

    //The Rest is left busybox sh and /etc/init.d/rcS for now
}

fn rcS(allc: Allocator) !void {
    var child = std.process.Child.init(&[_][]const u8{
        "/bin/sh",
        "/etc/init.d/rcS",
    }, allc);

    _ = try child.spawnAndWait();
}

fn sh(allc: Allocator) !void {
    var child = std.process.Child.init(&[_][]const u8{"/bin/sh"}, allc);

    _ = try child.spawnAndWait();
}

pub fn main() !void {
    const allc = std.heap.page_allocator;
    const is_init = std.os.linux.getpid() == 1;

    if (is_init) {
        log.info("Zig is running as init!", .{});
    } else {
        log.info("Zig is not running as init.", .{});
    }

    log.info("uname: {s} {s} {s} {s} {s} {s}", std.os.uname());

    if (is_init) {
        try init();
        try rcS(allc);
    }

    try sh(allc);
}
