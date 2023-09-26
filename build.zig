const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const init = b.addExecutable(.{
        .name = "m",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(init);

    const run_cmd = b.addRunArtifact(init);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const xplt = b.addExecutable(.{
        .name = "xplt",
        .root_source_file = .{ .path = "src/xplt.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(xplt);

    const fuse_tests = b.addTest(.{
        .name = "fuse-test",
        .root_source_file = .{ .path = "src/fuse.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(fuse_tests);

    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
