const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;

const Perm = enum(u8) {
    Exec = 0x1,
    Write = 0x2,
    Read = 0x4,
    _,
};

const Error = error{
    BadMemSize,
    BadAlignment,
    Permission,
    BadBitmapSize,
} || Allocator.Error;

fn MMU(
    comptime mem_size: usize,
    comptime base: usize,
) type {
    return struct {
        const Self = @This();

        allocator: Allocator,

        /// virtual memory for storing programs and code.
        memory: []u8,

        /// perms holds permissions bytes for each byte of virtual memory available
        perms: []u8,

        /// bitmap holds bytes indicating which blocks of memory have been allocated
        bitmap: []u8,

        pub fn init(allocator: Allocator) Error!Self {

            // memory size must be valid power of two so we can do bounds
            // checking with
            if (mem_size <= base or !std.mem.isValidAlign(mem_size) or mem_size < 32)
                return Error.BadMemSize;

            // base alloc must have a 32-bit alignment base
            assert(base != 0);
            if (base & 0x3 != 0)
                return Error.BadAlignment;

            const bitmap_size = mem_size / (base * 8);
            if (bitmap_size < 1) return Error.BadBitmapSize;

            var self = Self{
                .allocator = allocator,
                .memory = try allocator.alloc(u8, mem_size),
                .perms = try allocator.alloc(u8, mem_size),
                .bitmap = try allocator.alloc(u8, bitmap_size),
            };

            // discovered the hard way that heap allocated memory is not guaranteed
            // to be zero-ed out (i want to move back to golang :-/)
            for (self.perms) |*p| p.* = 0;
            for (self.bitmap) |*p| p.* = 0;

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.perms);
            self.allocator.free(self.memory);
            self.allocator.free(self.bitmap);
        }

        /// set permission on memory starting of `size` bytes starting at `addr`
        fn set_perms(self: *Self, addr: usize, size: usize, perm: Perm) void {
            if (debug)
                std.debug.print("[set_perms] start: {d}, end: {d}\n", .{ addr, addr + size });
            const start = addr - base;
            const end = start + size;
            for (self.perms[start..end]) |*b| b.* = @enumToInt(perm);

            // update the dirty bitmap
            for (start / base..(end + (base - 1)) / base) |ii| {
                const byte = ii / 8;
                const bit = @truncate(u3, ii % 8);
                self.bitmap[byte] |= @as(u8, 1) << bit;
                if (debug)
                    std.debug.print(
                        "bitmap[{d}] = {b}, bit: {d}, idx: {d}\n",
                        .{ byte, self.bitmap[byte], bit, ii },
                    );
            }
        }

        pub fn reset_to(self: *Self, other: *Self) void {
            for (other.bitmap[0..], 0..) |byte, ii| {

                // continue if byte is not dirty
                if (byte == 0) continue;

                // I think reset's should reset the other and then there should be
                // a clone function for doing clones (which is what this function
                // is doing at the moment)
                //
                // swap out the dirty byte from dirty byte with zero, indicating
                // its no longer dirty.
                // var tmp = @as(u8, 0);
                // mem.swap(u8, byte, &tmp);

                var tmp = byte;

                inline for (0..8) |bit| {
                    if (tmp & (1 << @truncate(u3, bit)) != 0) {
                        const offset = (ii * base * 8) + bit * base;

                        std.mem.copy(
                            u8,
                            self.memory[offset .. offset + base],
                            other.memory[offset .. offset + base],
                        );

                        std.mem.copy(
                            u8,
                            self.perms[offset .. offset + base],
                            other.perms[offset .. offset + base],
                        );
                    }
                }
            }
        }

        // allocate memory and set specified permission byte `perm` on it
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

        // allocate read-write memory of `size`
        pub fn alloc(self: *Self, size: usize) ?usize {
            return self.alloc_perms(
                size,
                @intToEnum(Perm, @enumToInt(Perm.Read) | @enumToInt(Perm.Write)),
            );
        }

        // check if memory of `size` bytes starting at `addr` is set to `perm`
        fn perm_is(self: Self, addr: usize, size: usize, perm: Perm) bool {
            for (self.perms[addr .. addr + size]) |b| {
                if (b & @enumToInt(perm) != @enumToInt(perm))
                    return false;
            }
            return true;
        }

        /// NSFW: memory returned is owned by MMU object.
        ///
        /// return a slice of `size` bytes of memory starting at `addr`
        fn get_alloc_region(self: Self, addr: usize, size: usize, perm: ?Perm) Error![]u8 {
            if (!self.perm_is(addr, size, perm orelse .Read))
                return Error.Permission;
            return self.memory[addr .. addr + size];
        }

        /// read `size` bytes starting from `addr` into `buf`.
        /// default permission is Perm.Read
        pub fn read_into(self: *Self, addr: usize, buf: []u8, perm: ?Perm) Error!void {
            const bytes = try self.get_alloc_region(addr, buf.len, perm);
            for (bytes, buf) |b, *d| d.* = b;
        }

        // write `buf.len` bytes starting at `addr` into memory.
        // defualt permission is Perm.Write
        pub fn write_from(self: *Self, addr: usize, buf: []const u8, perm: ?Perm) Error!void {
            const bytes = try self.get_alloc_region(addr, buf.len, perm orelse .Write);
            for (bytes, buf) |*b, d| b.* = d;
        }

        // write primitive integer `val` into memory starting at addr
        pub fn write_from_val(self: *Self, comptime T: type, addr: usize, val: T) Error!void {
            const bytes = mem.toBytes(mem.nativeToLittle(T, val));
            return self.write_from(addr, bytes[0..], null);
        }

        // read from memory into a primitive integer type
        pub fn read_into_val(self: Self, comptime T: type, addr: usize) Error!T {
            var bytes = try self.get_alloc_region(addr, @sizeOf(T), Perm.Read);
            return mem.littleToNative(
                T,
                mem.bytesToValue(T, @ptrCast(*[@sizeOf(T)]u8, bytes.ptr)),
            );
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

    var mmu = try MMU(0x100_000, 0x100).init(allocator);
    defer mmu.deinit();
    var addr = mmu.alloc(0xfff) orelse unreachable;
    var addr2 = mmu.alloc(0x100) orelse unreachable;
    try testing.expect(std.mem.isAligned(addr, 16));
    try testing.expect(std.mem.isAligned(addr2, 16));
    // std.debug.print("addr1: 0x{x}, addr2: 0x{x}\n", .{ addr, addr2 });
}

test "allocate and write to memory" {
    // var some_buf = try testing.allocator.alloc(u8, 2);
    // defer testing.allocator.free(some_buf);
    // std.debug.print("before write: {any}\n", .{some_buf});
    // for (some_buf) |*b| b.* = 2;
    // std.debug.print("after write: {any}\n", .{some_buf});

    var mmu = try MMU(256, 16).init(testing.allocator);
    defer mmu.deinit();
    try testing.expect(mmu.alloc(0xff) == null);

    const hello = "hello";
    var addr = mmu.alloc(hello.len) orelse unreachable;
    try testing.expect(std.mem.isValidAlign(addr));

    var addr2 = mmu.alloc(24) orelse unreachable;
    try testing.expect(std.mem.isValidAlign(addr2));

    // std.debug.print("addr1: {x}, addr2: {x}\n", .{ addr, addr2 });

    var region = try mmu.get_alloc_region(addr, hello.len, null);
    try testing.expectEqual(region.len, hello.len);
}

test "allocate, write and read memory" {
    const allocator = testing.allocator;
    var mmu = try MMU(256, 16).init(allocator);
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

test "read and write primitives" {
    var mmu = try MMU(0x1000, 0x10).init(testing.allocator);
    defer mmu.deinit();

    const num: u32 = 10;
    const num_type = @TypeOf(num);
    var num_addr = mmu.alloc(@sizeOf(num_type)) orelse unreachable;
    try mmu.write_from_val(num_type, num_addr, num);
    try testing.expect(try mmu.read_into_val(num_type, num_addr) == num);

    const list_type = i64;
    const numbers = [_]list_type{ -1, 444, 4445, 0x1000, 0xdeadbeef, -11283737 };
    const list_size = @sizeOf(list_type) * numbers.len;
    const list_addr = mmu.alloc(list_size) orelse unreachable;

    for (numbers, 0..) |elem, ii| {
        const addr = list_addr + @sizeOf(list_type) * ii;
        try mmu.write_from_val(list_type, addr, elem);
    }

    for (numbers, 0..) |elem, ii| {
        const addr = list_addr + @sizeOf(list_type) * ii;
        try testing.expect(try mmu.read_into_val(list_type, addr) == elem);
    }
}

test "clone another mmu's address space" {
    const size = 0x1000;
    const base = 0x10;
    var mmu = try MMU(size, base).init(testing.allocator);
    defer mmu.deinit();

    // read a bunch of text data into memory
    const text = "this is a bunch of text that say nothing important!";
    var addr = mmu.alloc(text.len) orelse unreachable;
    try mmu.write_from(addr, text[0..], null);
    var buf: [text.len]u8 = undefined;
    try mmu.read_into(addr, &buf, null);
    try testing.expect(mem.eql(u8, text, &buf));

    var other = try MMU(size, base).init(testing.allocator);
    defer other.deinit();

    // clone the other memory
    other.reset_to(&mmu);

    var buffer: [text.len]u8 = undefined;
    try other.read_into(addr, &buffer, null);
    try testing.expect(mem.eql(u8, text, &buffer));
}

test "clone in parrallel (why??.. cos its fun!)" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    const Atomic = std.atomic.Atomic;
    const Timer = std.time.Timer;
    const Thread = std.Thread;

    const size = 0x1000;
    const base = 0x10;
    var mmu = try MMU(size, base).init(testing.allocator);
    defer mmu.deinit();

    // read a bunch of text data into memory
    const text = "this is a bunch of text that say nothing important!";
    var addr = mmu.alloc(text.len) orelse unreachable;
    try mmu.write_from(addr, text[0..], null);

    const Worker = struct {
        time_elapsed: Atomic(u64) = Atomic(u64).init(0),

        fn run(self: *@This(), memory: *MMU(size, base), clone_addr: usize, data: []const u8) !void {
            var timer = try Timer.start();

            var other = try MMU(size, base).init(testing.allocator);
            defer other.deinit();

            // clone the other memory
            other.reset_to(memory);

            var buffer: [text.len]u8 = undefined;
            try other.read_into(clone_addr, &buffer, null);
            try testing.expect(mem.eql(u8, data, &buffer));

            _ = self.time_elapsed.fetchAdd(timer.lap(), .SeqCst);
        }
    };

    var worker = Worker{};

    const num_threads = 10000;
    var threads: [num_threads]Thread = undefined;
    for (&threads) |*t| t.* = try Thread.spawn(
        .{},
        Worker.run,
        .{ &worker, &mmu, addr, text[0..] },
    );
    for (threads) |t| t.join();

    std.debug.print("\naveraged time to clone {d} MMU(s) is {d:.3}ns\n", .{
        num_threads,
        @intToFloat(f64, worker.time_elapsed.load(.SeqCst)) / @intToFloat(f64, num_threads),
    });
}
