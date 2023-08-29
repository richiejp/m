const std = @import("std");
const os = std.os;
const errno = os.errno;
const l = os.linux;
const mem = std.mem;
const log = std.log;

const Self = @This();
const NUM_SKS = 8;
const NUM_SKBUFFS = 128;

sks: [4][2]l.fd_t,

pub fn init() !Self {
    var self: Self = undefined;

    for (&self.sks) |*pair| {
        const ret = errno(l.socketpair(l.AF.UNIX, l.SOCK.STREAM, 0, pair));

        if (ret != .SUCCESS) {
            log.err("socketpair = {}", .{ret});
            return error.socketpairFailed;
        }

        errdefer os.closeSocket(pair[0]);
        errdefer os.closeSocket(pair[1]);
    }

    return self;
}

pub fn deinit(self: Self) void {
    for (self.sks) |pair| {
        os.closeSocket(pair[0]);
        os.closeSocket(pair[1]);
    }
}

pub fn spray(self: Self, out: []const u8) !void {
    var n: u16 = 0;

    for (self.sks) |pair| {
        while (n < NUM_SKBUFFS) : (n += 1) {
            _ = try os.write(pair[0], out);
        }
    }
}

pub fn read(self: Self, out: []const u8, in: []u8) !void {
    var n: u16 = 0;

    for (self.sks) |pair| {
        while (n < NUM_SKBUFFS) : (n += 1) {
            _ = try os.read(pair[1], in);

            if (!mem.eql(u8, out, in))
                return;
        }
    }

    return error.noSkbuffOverwritten;
}
