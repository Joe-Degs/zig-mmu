/// This file contains code for testing out ideas for tracking dirty-ed memory
/// blocks in a virtual address space of a program so we can do resets or forks
/// fast. It uses a bitmap array to track blocks that have been dirty-ed i.e
/// allocated for use.
/// This method (which depends on the granularity of blocks) prevents us
/// from looping through memory by byte looking for non-zero bytes.
const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;

pub fn main() !void {
    const virtaddr = struct {
        const Self = @This();

        const size: usize = 256;
        const base: usize = 8;

        // bitmap for tracking memory that is in use (dirtied). our bitmap can
        // represent all `size` bytes of memory at the granularity of base which
        // supposed to be a valid alignment. we could preset the granularity but
        // that would not be very flexible. I favour 256 bytes as that allows
        // us to do sift through memory for used blocks without spending too much
        // time.
        // Also since we use the granularity to keep track of the memory that is in
        // use, it will not be advisable to use this same bitmap for allocations since
        // it tracks memory in bigger chunks than we might probably be allocating.
        //
        // for testing purposes we keep these numbers small so we can wrap our heads
        // around it.
        const bitmap_size = size / (base * 8);

        memory: [size]u8,
        permissions: [size]u8,
        bitmap: [bitmap_size]u8,
        last_alloc: usize,

        fn init() Self {
            var self = .{
                .memory = [_]u8{0} ** size,
                .permissions = [_]u8{0} ** size,
                .bitmap = [_]u8{0} ** bitmap_size,
                .last_alloc = base,
            };

            assert(mem.isValidAlign(base));

            std.debug.print(
                "mem_size: {x}, granularity: {x} bitmap_size: {x}\n",
                .{ size, base, bitmap_size },
            );

            return self;
        }

        fn alloc(self: *Self, n: usize) usize {
            const aligned_size = (n + 0xf) & ~@as(usize, 0xf);
            assert(self.last_alloc + aligned_size <= size);
            const prev_offset = self.last_alloc;
            self.last_alloc += aligned_size;
            std.debug.print(
                "\naddr: {d} next: {d}, aligned_size: {d}\n",
                .{ prev_offset, self.last_alloc, aligned_size },
            );

            // update the bitmap
            const end = (self.last_alloc + (base - 1)) / base;
            std.debug.print(
                "dirty update: start: {d}, end: {d}\n",
                .{ prev_offset / base, end },
            );
            for (prev_offset / base..end) |ii| {
                const byte = ii / 8;
                const bit = @truncate(u3, ii % 8);
                self.bitmap[byte] |= @as(u8, 1) << bit;
                std.debug.print(
                    "bitmap[{d}] = {b}, bit: {d}, idx: {d}\n",
                    .{ byte, self.bitmap[byte], bit, ii },
                );
            }

            return prev_offset;
        }

        fn reset_to(self: *Self, other: *Self) void {
            for (other.bitmap[0..], 0..) |*byte, ii| {

                // continue if byte is not dirty
                if (byte.* == 0) continue;

                // swap out the dirty byte from dirty byte with zero, indicating
                // its no longer dirty.
                var tmp = @as(u8, 0);
                mem.swap(u8, byte, &tmp);

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
                            self.permissions[offset .. offset + base],
                            other.permissions[offset .. offset + base],
                        );
                    }
                }
            }
        }

        fn write(self: *Self, addr: usize, buf: []const u8) void {
            var bytes = self.memory[addr .. addr + buf.len];
            mem.copy(u8, bytes[0..], buf);
        }

        fn read(self: Self, addr: usize, buf: []u8) void {
            mem.copy(u8, buf, self.memory[addr .. addr + buf.len]);
        }
    };

    var mmu = virtaddr.init();
    var hello_addr = mmu.alloc(0xf);
    mmu.write(hello_addr, "helllooooooooo");
    var world_addr = mmu.alloc(40);
    mmu.write(world_addr, "worldddddd");
    _ = mmu.alloc(50);

    var other_mmu = virtaddr.init();
    other_mmu.reset_to(&mmu);

    assert(mem.eql(u8, mmu.memory[0..], other_mmu.memory[0..]));

    var buffer: [40]u8 = undefined;
    other_mmu.read(hello_addr, buffer[0..16]);
    std.debug.print("{s} ", .{&buffer});

    other_mmu.read(world_addr, &buffer);
    std.debug.print("{s}\n", .{&buffer});
}
