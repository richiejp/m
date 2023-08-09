const std = @import("std");
const log = std.log;
const info = std.log.info;
const fs = std.fs;
const os = std.os;
const errno = os.errno;
const linux = os.linux;
const E = linux.E;
const mem = std.mem;

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

    info("ls {s}", .{path});

    while (try itr.next()) |entry| {
        const t = switch (entry.kind) {
            .directory => "dir",
            .file => "file",
            .block_device, .character_device => "dev",
            else => "other",
        };

        info("{s:5}: {s}", .{ t, entry.name });
    }
}

fn mvRec(src: fs.Dir, dst: fs.Dir) !void {
    var isrc = try src.openIterableDir(".", .{});
    defer isrc.close();
    var itr = isrc.iterateAssumeFirstIteration();

    const dst_stat = try os.fstat(dst.fd);
    const src_stat = try os.fstat(src.fd);

    while (try itr.next()) |base| {
        switch (base.kind) {
            .file => {
                info("mv file {s}", .{base.name});

                try src.copyFile(base.name, dst, base.name, .{});
                try src.deleteFile(base.name);
            },
            .sym_link => {
                info("ln {s}", .{base.name});
                var buf: [linux.PATH_MAX]u8 = undefined;

                const link = try src.readLink(base.name, &buf);
                try dst.symLink(link, base.name, .{});
                try src.deleteFile(base.name);
            },
            .directory => {
                var sub_src = try src.openDir(base.name, .{});
                defer sub_src.close();
                const sub_src_stat = try os.fstat(sub_src.fd);

                if (sub_src_stat.ino == dst_stat.ino) {
                    info("skip dir {s}", .{base.name});
                    continue;
                }

                var sub_dst = try mkpath(dst, base.name, 0o755);
                defer sub_dst.close();

                if (src_stat.dev != sub_src_stat.dev) {
                    info("shallow mv {s}", .{base.name});
                    continue;
                }

                info("mv dir {s}", .{base.name});
                try mvRec(sub_src, sub_dst);
                try src.deleteDir(base.name);
            },
            else => continue,
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

    {
        var new_root = try mkpath(old_root, "newroot", 0o700);
        defer new_root.close();
        const data: [*:0]const u8 = "size=100240k";
        try mount("none", "/newroot", "tmpfs", 0, @intFromPtr(data));
        info("Temporarily mounted new root at /newroot", .{});
    }

    var new_root = try old_root.openDir("newroot", .{});
    defer new_root.close();
    try mvRec(old_root, new_root);
    info("Moved root contents to /newroot", .{});

    try mount("/newroot", "/", ":-)", MS_MOVE, 0);
    info("Moved /newroot to /", .{});

    try chroot("/");
    try std.os.chdir(".");
    info("chrooted into new /", .{});
}

fn init() !void {
    try ls("/");
    info("Switching root away from rootfs because of pivot_root", .{});
    try switch_root();
    try ls("/");
}

pub fn main() !void {
    const is_init = std.os.linux.getpid() == 1;

    if (is_init) {
        info("Zig is running as init!", .{});
    } else {
        info("Zig is not running as init.", .{});
    }

    info("uname: {s} {s} {s} {s} {s} {s}", std.os.uname());

    init() catch |err| {
        log.err("during setup: {}:", .{err});

        if (@errorReturnTrace()) |bt|
            std.debug.dumpStackTrace(bt.*);
    };

    while (true) {
        _ = linux.syscall0(.pause);
        _ = std.os.waitpid(-1, 0);
    }
}
