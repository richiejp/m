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

const MIN_READ_BUFFER = 8192;

const Opcode = enum(u32) {
    LOOKUP = 1,
    FORGET = 2,
    GETATTR = 3,
    SETATTR = 4,
    READLINK = 5,
    SYMLINK = 6,
    MKNOD = 8,
    MKDIR = 9,
    UNLINK = 10,
    RMDIR = 11,
    RENAME = 12,
    LINK = 13,
    OPEN = 14,
    READ = 15,
    WRITE = 16,
    STATFS = 17,
    RELEASE = 18,
    FSYNC = 20,
    SETXATTR = 21,
    GETXATTR = 22,
    LISTXATTR = 23,
    REMOVEXATTR = 24,
    FLUSH = 25,
    INIT = 26,
    OPENDIR = 27,
    READDIR = 28,
    RELEASEDIR = 29,
    FSYNCDIR = 30,
    GETLK = 31,
    SETLK = 32,
    SETLKW = 33,
    ACCESS = 34,
    CREATE = 35,
    INTERRUPT = 36,
    BMAP = 37,
    DESTROY = 38,
    IOCTL = 39,
    POLL = 40,
    NOTIFY_REPLY = 41,
    BATCH_FORGET = 42,
    FALLOCATE = 43,
    READDIRPLUS = 44,
    RENAME2 = 45,
    LSEEK = 46,
    COPY_FILE_RANGE = 47,
    SETUPMAPPING = 48,
    REMOVEMAPPING = 49,
    SYNCFS = 50,
    TMPFILE = 51,

    CUSE_INIT = 4096,

    CUSE_INIT_BSWAP_RESERVED = 1048576,
    INIT_BSWAP_RESERVED = 436207616,
};

const FATTR = struct {
    pub const MODE = @as(u32, 1) << @as(u32, 0);
    pub const UID = @as(u32, 1) << @as(u32, 1);
    pub const GID = @as(u32, 1) << @as(u32, 2);
    pub const SIZE = @as(u32, 1) << @as(u32, 3);
    pub const ATIME = @as(u32, 1) << @as(u32, 4);
    pub const MTIME = @as(u32, 1) << @as(u32, 5);
    pub const FH = @as(u32, 1) << @as(u32, 6);
    pub const ATIME_NOW = @as(u32, 1) << @as(u32, 7);
    pub const MTIME_NOW = @as(u32, 1) << @as(u32, 8);
    pub const LOCKOWNER = @as(u32, 1) << @as(u32, 9);
    pub const CTIME = @as(u32, 1) << @as(u32, 10);
    pub const KILL_SUIDGID = @as(u32, 1) << @as(u32, 11);
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
    flags2: u32,
    unused: [11]u32,
};

const InitOut = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,

    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
    unused: [7]u32 = .{0} ** 7,
};

const InitOutMsg = extern struct {
    head: OutHeader,
    body: InitOut,
};

const GetattrIn = extern struct {
    flags: u32,
    dummy: u32,
    fh: u64,
};

const Attr = extern struct {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    flags: u32,
};

const AttrOut = extern struct {
    valid: u64,
    valid_nsec: u32,
    dummy: u32,
    attr: Attr,
};

const ValidAttrs = packed struct {};

const SetattrIn = extern struct {
    valid: u32,
    padding: u32,
    fh: u64,
    size: u64,
    lock_owner: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    unused4: u32,
    uid: u32,
    gid: u32,
    unused5: u32,
};

const EntryOut = extern struct {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: Attr,
};

const SetxattrIn = extern struct {
    size: u32,
    flags: u32,
    setxattr_flags: u32,
    padding: u32 = 0,
};

const SetxattrInReq = struct {
    hdr: SetxattrIn,
    name: [:0]const u8,
    value: []const u8,
};

const Request = struct { hdr: InHeader, body: union(enum) {
    getattr: GetattrIn,
    setattr: SetattrIn,
    lookup: []const u8,
    setxattr: SetxattrInReq,

    other: Opcode,
} };

const OutUnion = extern union {
    init: InitOut,
    attr: AttrOut,
    entry: EntryOut,
};

const Response = extern struct {
    hdr: OutHeader,
    out: OutUnion,

    pub fn init(req: Request) Response {
        return Response{
            .hdr = .{
                .len = @sizeOf(OutHeader),
                .unique = req.hdr.unique,
                .err = 0,
            },
            .out = undefined,
        };
    }

    pub fn send(self: Response, fd: os.fd_t) !void {
        var to_write: []u8 align(1) = mem.asBytes(&self)[0..self.hdr.len];

        while (to_write.len > 0) {
            const written = try os.write(fd, to_write);
            to_write = to_write[written..];
        }
    }
};

comptime {
    assert(@sizeOf(Response) == @sizeOf(OutHeader) + @sizeOf(OutUnion));
}

const MNT = struct {
    const NOSUID = 0x02;
    const NODEV = 0x04;
    const NOEXEC = 0x08;
};

pub const Ops = struct {
    onSetxattr: ?fn (name: [:0]const u8, value: []const u8) void,
};

const S = @This();
const XATTR_NAME: [:0]const u8 = "user.bar";

dev: fs.File,
path: [fs.MAX_PATH_BYTES - 1:0]u8,

read_len: usize = 0,
read_buf: [MIN_READ_BUFFER * 2]u8 = undefined,

fn umount(self: S) void {
    const ret = os.errno(l.umount(&self.path));

    if (ret != .SUCCESS)
        log.err("fuse: umount {s}: {}", .{ &self.path, ret });
}

pub fn init(dir: fs.Dir) !S {
    var self = blk: {
        var real_path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try dir.realpath(".", &real_path_buf);

        break :blk S{
            .dev = try fs.openFileAbsolute("/dev/fuse", .{ .mode = .read_write }),
            .path = try os.toPosixPath(path),
        };
    };

    const fd = self.dev.handle;

    {
        const uid = l.geteuid();
        const gid = l.getegid();
        var buf: [64]u8 = .{0} ** 64;
        const opts = try std.fmt.bufPrintZ(&buf, "fd={},rootmode=40000,user_id={},group_id={}", .{ self.dev.handle, uid, gid });

        const ret = l.mount("fuse", &self.path, "fuse.fuse", MNT.NODEV | MNT.NOSUID, @intFromPtr(opts.ptr));
        const err = os.errno(ret);

        if (err != .SUCCESS) {
            log.err("fuse: mount {s}: {}", .{ &self.path, err });
            unreachable;
        }

        errdefer self.umount();
    }

    {
        var buf: []u8 = &self.read_buf;
        const len = try os.read(fd, buf);

        assert(len >= @sizeOf(InHeader) + @sizeOf(InitIn));

        const hdr = mem.bytesAsValue(InHeader, buf[0..@sizeOf(InHeader)]);

        log.info("kernel: hdr: {}", .{hdr.*});

        const opcode: Opcode = @enumFromInt(hdr.opcode);
        assert(opcode == .INIT);
        assert(hdr.len == @sizeOf(InHeader) + @sizeOf(InitIn));

        self.read_len = len - hdr.len;

        const req = mem.bytesAsValue(InitIn, (buf[@sizeOf(InHeader)..][0..@sizeOf(InitIn)]));

        log.info("kernel: init: {}", .{req.*});

        assert(req.major == 7);
        assert(req.minor == 37);

        const res = InitOutMsg{
            .head = .{
                .len = @sizeOf(InitOutMsg),
                .err = 0,
                .unique = hdr.unique,
            },
            .body = .{
                .major = 7,
                .minor = 37,
                .max_readahead = req.max_readahead,
                .flags = req.flags,
                .flags2 = req.flags2,

                .max_background = 0,
                .congestion_threshold = 0,
                .max_write = 4096,
                .time_gran = 0,
                .max_pages = 1,
                .map_alignment = 1,
            },
        };

        log.info("fuse: init: {}", .{res});
        assert(try os.write(fd, mem.asBytes(&res)) == @sizeOf(@TypeOf(res)));

        mem.copyForwards(u8, buf, buf[@sizeOf(InHeader) + @sizeOf(InitIn) ..]);
    }

    return self;
}

pub fn deinit(self: S) void {
    self.dev.close();
    self.umount();
}

pub fn start_read_req(self: *S) !Request {
    const buf: []u8 = &self.read_buf;
    const fd = self.dev.handle;

    while (self.read_len < @sizeOf(InHeader)) {
        self.read_len += if (self.read_len < @sizeOf(InHeader))
            try os.read(fd, buf[self.read_len..])
        else
            0;
    }

    const hdr = mem.bytesAsValue(InHeader, buf[0..@sizeOf(InHeader)]);

    log.info("kernel: hdr:  {}", .{hdr});
    const opcode: Opcode = @enumFromInt(hdr.opcode);

    log.info("kernel: opcode: {}", .{opcode});

    assert(hdr.len <= MIN_READ_BUFFER);

    while (hdr.len > self.read_len)
        self.read_len += try os.read(fd, buf[self.read_len..]);

    const msg = buf[@sizeOf(InHeader)..hdr.len];
    const msg_len = hdr.len - @sizeOf(InHeader);

    var req = Request{
        .hdr = hdr,
        .body = .{ .other = opcode },
    };

    switch (opcode) {
        .GETATTR => {
            const getattr_in =
                mem.bytesAsValue(GetattrIn, msg[0..@sizeOf(GetattrIn)]);

            log.info("kernel: getattr: {}", .{getattr_in});

            req.body = .{ .getattr = getattr_in };
        },

        .SETATTR => {
            const setattr_in =
                mem.bytesAsValue(SetattrIn, msg[0..@sizeOf(SetattrIn)]);

            log.info("kernel: setattr: {}", .{setattr_in});

            req.body = .{ .setattr = setattr_in };
        },

        .LOOKUP => {
            const lookup_in: []const u8 = msg[0..msg_len];

            log.info("kernel: lookup: {s}", .{lookup_in});

            req.body = .{ .lookup = lookup_in };
        },

        .SETXATTR => {
            const xattr_in = mem.bytesToValue(SetxattrIn, msg[0..@sizeOf(SetxattrIn)]);
            const tail = msg[@sizeOf(SetxattrIn)..];

            log.info("kernel: setxattr: {}", .{xattr_in});

            const name_len = msg_len - @sizeOf(SetxattrIn) - xattr_in.size;
            const name = tail[0 .. name_len - 1 :0];
            const value = tail[name_len..];

            req.body = .{ .setxattr = .{
                .hdr = xattr_in,
                .name = name,
                .value = value,
            } };
        },

        else => {
            log.info("fuse: Not implemented: {}", .{opcode});
        },
    }

    return req;
}

pub fn done_read_req(self: *S, req: Request) void {
    const buf: []u8 = &self.read_buf;

    self.read_len -= req.hdr.len;
    mem.copyForwards(u8, buf, buf[req.hdr.len..]);
}

pub fn do_one(self: *S, comptime ops: Ops) !void {
    const req = try self.start_read_req();

    var res = Response.init(req);

    switch (req.body) {
        .getattr => {
            const time: u64 = @intCast(@min(0, std.time.timestamp()));

            res.out.attr = .{
                .valid = 0,
                .valid_nsec = 0,
                .dummy = 0,
                .attr = .{
                    .ino = req.hdr.nodeid,
                    .blocks = 1,
                    .size = 42,
                    .atime = time,
                    .mtime = time,
                    .ctime = time,
                    .atimensec = 0,
                    .mtimensec = 0,
                    .ctimensec = 0,
                    .mode = l.S.IFDIR | 0o666,
                    .nlink = 1,
                    .uid = l.getuid(),
                    .gid = l.getgid(),
                    .rdev = 0,
                    .blksize = 0,
                    .flags = 0,
                },
            };

            res.hdr.len += @sizeOf(AttrOut);
        },

        .setattr => |setattr_in| {
            const time: u64 = @intCast(@min(0, std.time.timestamp()));

            res.out.attr = .{
                .valid = 0,
                .valid_nsec = 0,
                .dummy = 0,
                .attr = .{
                    .ino = req.hdr.nodeid,
                    .blocks = 1,
                    .size = 42,
                    .atime = time,
                    .mtime = time,
                    .ctime = time,
                    .atimensec = 0,
                    .mtimensec = 0,
                    .ctimensec = 0,
                    .mode = l.S.IFDIR | 0o666,
                    .nlink = 1,
                    .uid = l.getuid(),
                    .gid = l.getgid(),
                    .rdev = 0,
                    .blksize = 0,
                    .flags = 0,
                },
            };

            const v = setattr_in.valid;
            if (v & ~(FATTR.ATIME | FATTR.MTIME | FATTR.CTIME) > 0) {
                log.info("setattr: setting attributes not supported", .{});
                res.hdr.err = -@as(i32, @intFromEnum(E.OPNOTSUPP));
            } else {
                res.hdr.len += @sizeOf(AttrOut);
            }
        },

        .lookup => |lookup_in| blk: {
            const Static = struct {
                var generation: u64 = 0;
            };

            if (!mem.eql(u8, "foo", lookup_in[0..3])) {
                res.hdr.err = -@as(i32, @intFromEnum(E.NOENT));
                break :blk;
            }

            const time: u64 = @intCast(@min(0, std.time.timestamp()));

            Static.generation += 1;

            res.out.entry = .{
                .nodeid = 0xf00,
                .generation = Static.generation,
                .entry_valid = 0,
                .entry_valid_nsec = 0,
                .attr_valid = 0,
                .attr_valid_nsec = 0,
                .attr = .{
                    .ino = 0xf00,
                    .blocks = 1,
                    .size = 420,
                    .atime = time,
                    .mtime = time,
                    .ctime = time,
                    .atimensec = 0,
                    .mtimensec = 0,
                    .ctimensec = 0,
                    .mode = l.S.IFREG | 0o666,
                    .nlink = 1,
                    .uid = l.getuid(),
                    .gid = l.getgid(),
                    .rdev = 0,
                    .blksize = 0,
                    .flags = 0,
                },
            };

            res.hdr.len += @sizeOf(EntryOut);
        },

        .setxattr => |xattr| {
            if (ops.onSetxattr != null)
                ops.onSetxattr.?(xattr.name, xattr.value);
        },
    }

    res.send(self.dev.handle);
    self.done_read_req(req);
}

pub fn more(self: *S) !bool {
    var fds = [_]os.pollfd{
        .{
            .fd = self.dev.handle,
            .events = os.POLL.IN,
            .revents = 0,
        },
    };

    const len = try os.poll(&fds, 10);

    assert(len < 2);
    assert(len == 0 or fds[0].revents & os.POLL.IN != 0);

    return len == 1;
}

pub fn getTmpDir(env: std.process.EnvMap) !fs.Dir {
    const tmp_dir_path = env.get("TMPDIR") orelse "/tmp";

    return try fs.openDirAbsolute(tmp_dir_path, .{});
}

pub fn mkTmpDir(basename: []const u8, env: std.process.EnvMap) !fs.Dir {
    var tmp_dir = try getTmpDir(env);
    defer tmp_dir.close();
    tmp_dir.makeDir(basename) catch |err| {
        if (err != error.PathAlreadyExists)
            return err;
    };

    return try tmp_dir.openDir(basename, .{});
}

pub fn realPosixPath(dir: fs.Dir, path: []const u8) ![fs.MAX_PATH_BYTES - 1:0]u8 {
    var buf: [os.PATH_MAX]u8 = .{0} ** os.PATH_MAX;

    return try os.toPosixPath(try dir.realpath(path, &buf));
}

const TestEnv = struct {
    dir: fs.Dir,

    const allc = std.testing.allocator;

    pub fn init() !TestEnv {
        var env = try std.process.getEnvMap(allc);
        defer env.deinit();

        return .{
            .dir = try mkTmpDir("fuse-test", env),
        };
    }

    pub fn deinit(self: *TestEnv) void {
        self.dir.close();
    }
};

test "init" {
    var env = try TestEnv.init();
    defer env.deinit();

    var mnt = try init(env.dir);
    defer mnt.deinit();

    assert(!try mnt.more());
}

pub fn setxattr(path: [*:0]const u8, name: [*:0]const u8, value: []const u8, size: usize, flags: usize) usize {
    return l.syscall5(.setxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value.ptr), size, flags);
}

fn setXAttr(env: *const TestEnv) void {
    const path_c = realPosixPath(env.dir, "foo") catch |err| {
        log.info("setxattr: realPosixPath: {}", .{err});
        return;
    };

    const res = setxattr(@ptrCast(&path_c), XATTR_NAME, "baz", 3, 0);
    const err = os.errno(res);

    log.info("setxattr: {}: {}", .{ env.dir, err });
}

fn setXAttrOp(name: [:0]const u8, value: []const u8) void {
    log.info("kernel: setxattr: [{}]{s} => {s}", .{ name.len, name, value });

    assert(mem.eql(u8, XATTR_NAME, name));
    assert(mem.eql(u8, "baz", value));
}

test "one" {
    var env = try TestEnv.init();
    defer env.deinit();

    var mnt = try init(env.dir);
    defer mnt.deinit();

    log.info("init: {}", .{env.dir});
    var thread = try std.Thread.spawn(.{}, setXAttr, .{&env});

    const ops = Ops{ .onSetxattr = setXAttrOp };
    try mnt.do_one(ops);
    try mnt.do_one(ops);
    try mnt.do_one(ops);
    try mnt.do_one(ops);

    assert(!try mnt.more());

    thread.join();
}
