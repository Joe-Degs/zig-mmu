const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;

const Perm = enum(u8) {
    Exec = 0x1,
    Write = 0x2,
    Read = 0x4,
    _,
};

const Error = error{ BadMemSize, BadAlignment, Permission } || Allocator.Error;

fn MMU(
    comptime mem_size: usize,
    comptime base: usize,
    // comptime dirty_sz: usize,
) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        memory: []u8,
        perms: []u8,

        pub fn init(allocator: Allocator) Error!Self {
            // _ = dirty_sz;

            // memory size must be valid power of two so we can do bounds
            // checking with
            if (!std.mem.isValidAlign(mem_size) or mem_size < 32)
                return Error.BadMemSize;

            // base alloc must have a 32-bit alignment base
            assert(base != 0);
            if (base & 0x3 != 0)
                return Error.BadAlignment;

            var self = Self{
                .allocator = allocator,
                .memory = try allocator.alloc(u8, mem_size),
                .perms = try allocator.alloc(u8, mem_size),
            };

            // discovered the hard way that heap allocated memory is not guaranteed
            // to be zero-ed out (i want to move back to golang :-/)
            for (self.perms) |*p| p.* = 0;

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.perms);
            self.allocator.free(self.memory);
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
                if (ii + size > self.perms.len) return null;

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
            );
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
            return self.memory[addr .. addr + size];
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

test "memory size and alignment" {
    const allocator = testing.allocator;
    try testing.expectError(Error.BadMemSize, MMU(0, 0).init(allocator));
    try testing.expectError(Error.BadMemSize, MMU(10, 16).init(allocator));
    try testing.expectError(Error.BadMemSize, MMU(0, 16).init(allocator));
    try testing.expectError(Error.BadAlignment, MMU(64, 10).init(allocator));
}

test "allocate and write to memory" {
    // var some_buf = try testing.allocator.alloc(u8, 2);
    // defer testing.allocator.free(some_buf);
    // std.debug.print("before write: {any}\n", .{some_buf});
    // for (some_buf) |*b| b.* = 2;
    // std.debug.print("after write: {any}\n", .{some_buf});

    var mmu = try MMU(64, 16).init(testing.allocator);
    defer mmu.deinit();
    try testing.expect(mmu.alloc(0xff) == null);

    const hello = "hello";
    var addr = mmu.alloc(hello.len) orelse unreachable;
    try testing.expect(std.mem.isValidAlign(addr));

    var addr2 = mmu.alloc(24) orelse unreachable;
    try testing.expect(std.mem.isValidAlign(addr2));

    std.debug.print("addr1: {x}, addr2: {x}\n", .{ addr, addr2 });

    var region = try mmu.get_alloc_region(addr, hello.len, null);
    try testing.expectEqual(region.len, hello.len);
}

test "allocate, write and read memory" {
    const allocator = testing.allocator;
    var mmu = try MMU(64, 16).init(allocator);
    defer mmu.deinit();
    const hello = "hello";
    var addr = mmu.alloc(hello.len) orelse unreachable;
    try mmu.write_from(addr, hello[0..], null);

    var region = try mmu.get_alloc_region(addr, hello.len, null);
    try testing.expect(std.mem.eql(u8, region, "hello"));

    var buf = [_]u8{0} ** hello.len;
    try mmu.read_into(addr, &buf, null);
    try testing.expect(std.mem.eql(u8, &buf, "hello"));
}

test "alloc big" {
    const allocator = testing.allocator;
    var mmu = try MMU(0x100_000, 0x100).init(allocator);
    defer mmu.deinit();
    var addr = mmu.alloc(0xfff) orelse unreachable;
    var addr2 = mmu.alloc(0x100) orelse unreachable;
    try testing.expect(std.mem.isValidAlign(addr));
    std.debug.print("addr1: 0x{x}, addr2: 0x{x}\n", .{ addr, addr2 });
}
