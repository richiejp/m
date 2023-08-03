const std = @import("std");
const log = std.log;
const info = std.log.info;
const fs = std.fs;
const linux = std.os.linux;
const E = linux.E;

fn mount(
    special: [*:0]const u8,
    dir: [*:0]const u8,
    fstype: [*:0]const u8,
    flags: u32,
    data: usize,
) !void {
    const ret: E =
        @enumFromInt(linux.mount(special, dir, fstype, flags, data));

    if (ret == E.SUCCESS)
        return;

    log.err("mount({s}, {s}, {s}, {}, {}) = {}", .{ special, dir, fstype, flags, data, ret });

    return error.mountFailed;
}

fn ls(dir: fs.Dir, path: []const u8) !void {
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

fn chmod(dir: fs.Dir, path: []const u8, mode: fs.File.Mode) !void {
    var sys = try dir.makeOpenPathIterable(path, .{});
    defer sys.close();

    try sys.chmod(mode);
}

fn init() !void {
    var root = try fs.openDirAbsolute("/", .{});
    defer root.close();

    try chmod(root, "sys", 0o555);
    try mount("none", "/sys", "sysfs", 0, 0);

    try ls(root, ".");
    try ls(root, "dev");
    try ls(root, "sys");
}

pub fn main() !void {
    const is_init = std.os.linux.getpid() == 1;

    if (is_init) {
        info("Zig is running as init!", .{});
    } else {
        info("Zig is not running as init.", .{});
    }

    info("uname: {s} {s} {s} {s} {s} {s}", std.os.uname());

    if (is_init) {
        init() catch |err| {
            if (@errorReturnTrace()) |bt| {
                log.err("during setup: {}: {}", .{ err, bt });
            } else {
                log.err("during setup: {}", .{err});
            }
        };
    }

    while (is_init) {
        std.time.sleep(100000);
    }
}
