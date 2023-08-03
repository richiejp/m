const std = @import("std");
const info = std.log.info;

pub fn main() !void {
    const is_init = std.os.linux.getpid() == 1;

    if (is_init) {
        info("Zig is running as init!", .{});
    } else {
        info("Zig is not running as init.", .{});
    }

    info("uname: {s} {s} {s} {s} {s} {s}", std.os.uname());

    while (is_init) {
        std.time.sleep(100000);
    }
}
