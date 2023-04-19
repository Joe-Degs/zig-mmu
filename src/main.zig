const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const Perm = enum(u8) {
    Exec = 0x1,
    Write = 0x2,
    Read = 0x4,
    _,
};

const Error = error{ BadMemSize, BadAlignment, Permission };

fn MMU(
    comptime mem_size: usize,
    comptime base: usize,
    // comptime dirty_sz: usize,
) Error!type {
    // _ = dirty_sz;

    // memory size must be valid power of two so we can do bounds
    // checking with
    if (!std.mem.isValidAlign(mem_size))
        return Error.BadMemSize;

    // base alloc must have a 32-bit alignment base
    assert(base != 0);
    if (base & 0x3 != 0)
        return Error.BadAlignment;

    return struct {
        mmu: [mem_size]u8 = undefined,
        perms: [mem_size]u8 = undefined,

        pub const Self = @This();

        pub fn init() Self {
            return .{
                .mmu = std.mem.zeroes([mem_size]u8),
                .perms = std.mem.zeroes([mem_size]u8),
            };
        }

        /// set permission on memory starting of `size` bytes starting at `addr`
        fn set_perms(self: *Self, addr: usize, size: usize, perm: Perm) void {
            if (debug)
                std.debug.print("[set_perms] start: {d}, end: {d}\n", .{ addr, addr + size });
            var start = addr - base;
            for (self.perms[start .. start + size]) |*b| b.* = @enumToInt(perm);
        }

        pub fn alloc_perms(self: *Self, size: usize, perm: Perm) ?usize {
            if (debug)
                std.debug.print("[alloc_perms] size: {d} perm: {any}\n", .{ size, perm });

            // we step through memory looking for space
            var ii: usize = 16;
            while (ii < self.perms.len) : (ii += 16) {
                if (ii + size > self.perms.len)
                    return null;

                // if permissions on memory are set we continue our search
                if (std.mem.allEqual(u8, self.perms[ii .. ii + size], 0)) {
                    self.set_perms(base + ii, size, perm);
                    return ii;
                }
            }
            return null;
        }

        pub fn alloc(self: *Self, size: usize) ?usize {
            return self.alloc_perms(
                size,
                @intToEnum(Perm, @enumToInt(Perm.Read) | @enumToInt(Perm.Write)),
            ).?;
        }

        fn perm_is(self: *Self, addr: usize, size: usize, perm: Perm) bool {
            for (self.perms[addr .. addr + size]) |b| {
                if (b & @enumToInt(perm) != @enumToInt(perm))
                    return false;
            }
            return true;
        }

        /// NSFW
        /// return a slice of `size` bytes of allocated memory starting at `addr`
        fn get_alloc_region(self: *Self, addr: usize, size: usize, perm: ?Perm) Error![]u8 {
            if (!self.perm_is(addr, size, perm orelse Perm.Read))
                return Error.Permission;
            return self.mmu[addr .. addr + size];
        }

        /// read `size` bytes starting from `addr` into `buf`.
        /// default permission is Perm.Read
        pub fn read_into(self: *Self, addr: usize, buf: []u8, perm: ?Perm) Error!void {
            var mem = try self.get_alloc_region(addr, buf.len, perm);
            for (mem, buf) |b, *d| d.* = b;
        }

        // write `buf.len` bytes starting at `addr` into memory.
        // defualt permission is Perm.Write
        pub fn write_from(self: *Self, addr: usize, buf: []const u8, perm: ?Perm) Error!void {
            var mem = try self.get_alloc_region(addr, buf.len, perm orelse Perm.Write);
            for (mem, buf) |*b, d| b.* = d;
        }
    };
}

const debug = false;

test "mem_size alignment/initial alloc" {
    try testing.expectError(Error.BadMemSize, MMU(0, 0));
    try testing.expectError(Error.BadMemSize, MMU(10, 16));
    try testing.expectError(Error.BadMemSize, MMU(0, 16));
    try testing.expectError(Error.BadAlignment, MMU(16, 10));

    var mmu = (try MMU(64, 16)).init();
    const hello = "hello";
    var addr = mmu.alloc(hello.len).?;
    try testing.expect(std.mem.isValidAlign(addr));

    var addr2 = mmu.alloc(24).?;
    try testing.expect(std.mem.isValidAlign(addr2));

    std.debug.print("addr1: {x}, addr2: {x}\n", .{ addr, addr2 });

    var region = try mmu.get_alloc_region(addr, hello.len, null);
    try testing.expectEqual(region.len, hello.len);
}

test "alloc-write-read hello" {
    var mmu = (try MMU(64, 16)).init();
    const hello = "hello";
    var addr = mmu.alloc(hello.len).?;
    try mmu.write_from(addr, hello[0..], null);

    var region = try mmu.get_alloc_region(addr, hello.len, null);
    try testing.expect(std.mem.eql(u8, region, "hello"));

    var buf = [_]u8{0} ** hello.len;
    try mmu.read_into(addr, &buf, null);
    try testing.expect(std.mem.eql(u8, &buf, "hello"));
}

test "alloc big" {
    var mmu = (try MMU(0x100_000, 0x100)).init();
    var addr = mmu.alloc(0xfff).?;
    try testing.expect(std.mem.isValidAlign(addr));
    std.debug.print("big addr: 0x{x}\n", .{addr});
}
