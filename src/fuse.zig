const std = @import("std");
const assert = std.debug.assert;
const log = std.log;
const net = std.net;
const os = std.os;
const fs = std.fs;
const errno = os.errno;
const l = os.linux;
const E = l.E;
const mem = std.mem;
const Allocator = mem.Allocator;

const Opcode = enum(u32) {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    FUSE_IOCTL = 39,
    FUSE_POLL = 40,
    FUSE_NOTIFY_REPLY = 41,
    FUSE_BATCH_FORGET = 42,
    FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44,
    FUSE_RENAME2 = 45,
    FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47,
    FUSE_SETUPMAPPING = 48,
    FUSE_REMOVEMAPPING = 49,
    FUSE_SYNCFS = 50,
    FUSE_TMPFILE = 51,

    CUSE_INIT = 4096,

    CUSE_INIT_BSWAP_RESERVED = 1048576,
    FUSE_INIT_BSWAP_RESERVED = 436207616,
};

const InHeader = extern struct {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,

    uid: l.uid_t,
    gid: l.gid_t,
    pid: l.pid_t,

    padding: u32,
};

const OutHeader = extern struct {
    len: u32,
    err: i32,
    unique: u64,
};

const InitIn = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
};

const InitOut = extern struct {
    common: InitIn,

    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    unused: [9]u32 = .{0} ** 9,
};

const InitOutMsg = extern struct {
    head: OutHeader,
    body: InitOut,
};

const MNT = struct {
    const NOSUID = 0x01;
    const NODEV = 0x02;
    const NOEXEC = 0x04;
};

const S = @This();

dev: fs.File,

pub fn init(path: [*:0]const u8) !S {
    var self = S{
        .dev = try fs.openFileAbsolute("/dev/fuse", .{ .mode = .read_write }),
    };
    const fd = self.dev.handle;

    {
        const uid = l.geteuid();
        const gid = l.getegid();
        var buf: [64]u8 = .{0} ** 64;
        const opts = try std.fmt.bufPrintZ(&buf, "fd={},rootmode=40000,user_id={},group_id={}", .{ self.dev.handle, uid, gid });

        const ret = l.mount("fuse", path, "fuse.fuse", MNT.NODEV | MNT.NOSUID, @intFromPtr(opts.ptr));
        const err = os.errno(ret);

        if (err != .SUCCESS) {
            log.err("fuse: mount: {}", .{err});
            unreachable;
        }
    }

    {
        var buf: [@sizeOf(InHeader) + @sizeOf(InitIn)]u8 = undefined;

        if (try os.read(fd, &buf) != buf.len)
            unreachable;

        const hdr: *InHeader = @ptrCast(@alignCast(buf[0..@sizeOf(InHeader)]));

        log.info("kernel: hdr: {}", .{hdr.*});

        const opcode: Opcode = @enumFromInt(hdr.opcode);
        if (opcode != .FUSE_INIT)
            unreachable;

        if (hdr.len != @sizeOf(InitIn))
            unreachable;

        const req: *InitIn = @ptrCast(@alignCast(buf[0..@sizeOf(InitIn)]));

        log.info("kernel: init: {}", .{req.*});

        if (req.major != 7)
            unreachable;

        if (req.minor != 37)
            unreachable;

        const res = InitOutMsg{
            .head = .{
                .len = @sizeOf(InitOut),
                .err = 0,
                .unique = hdr.unique,
            },
            .body = .{
                .common = req.*,

                .max_background = 0,
                .congestion_threshold = 0,
                .max_write = 4096,
                .time_gran = 0,
            },
        };

        if (try os.write(fd, mem.asBytes(&res)) != @sizeOf(@TypeOf(res)))
            unreachable;
    }

    return self;
}

pub fn deinit(self: S) void {
    self.dev.close();
}

test "init" {
    const allc = std.testing.allocator;
    var env = try std.process.getEnvMap(allc);
    defer env.deinit();
    const tmp_dir_path = env.get("TMPDIR") orelse "/tmp";

    var tmp_dir = try fs.openDirAbsolute(tmp_dir_path, .{});
    tmp_dir.makeDir("fuse-test") catch |err| {
        if (err != error.PathAlreadyExists)
            return err;
    };

    var buf = [_]u8{0} ** fs.MAX_PATH_BYTES;
    const mnt_path: [*:0]u8 = @ptrCast(try tmp_dir.realpath("fuse-test", buf[0 .. buf.len - 1]));
    var mnt = try init(mnt_path);
    defer mnt.deinit();
}
