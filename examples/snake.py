# Snake, with the game in the kernel.
#
# A port of bpfsnake (github.com/amiremohamadi/bpfsnake), a bpftrace script.
# The eBPF side keeps the whole game state in maps and runs the game logic:
# steering, moving, collisions, eating and growing. Python only draws the board
# the kernel left in the maps, because bpftrace's printf is an event sent to
# userspace and has no counterpart inside an eBPF program.
#
# Steering comes from a kprobe on pty_write, as in the original: a terminal
# echoes each typed byte back with a one-byte write, so an arrow key's final
# byte ('A' up, 'B' down, 'D' left; anything else is right) lands in `key`.
# Leave the terminal's echo on, it is what the probe sees.
#
# bpftrace's `interval:ms:120` would be a perf_event program, which pylibbpf
# cannot attach yet. Instead Python drives the clock: every tick it calls
# getppid(), and a kprobe on that syscall, filtered to this process, advances
# the game one step.
#
# Run `sudo /path/to/python examples/snake.py` from a terminal at least 50
# columns wide. Ctrl-C quits. x86_64 only (pt_regs registers, syscall name).

import os
import sys
import termios
import time
from ctypes import c_int8, c_int64, c_uint64

from vmlinux import struct_pt_regs

from pythonbpf import BPF, bpf, bpfglobal, map, section
from pythonbpf.helper import pid, probe_read_kernel, random
from pythonbpf.maps import HashMap

MAX_LENGTH = 10
WIDTH = 50
HEIGHT = 12

# Slots in the `state` map. The eBPF functions spell them as literals: module
# constants are not visible inside them.
FOODX, FOODY, GAME_OVER, PLAYER = 0, 1, 2, 3


# Body segment i sits at row snakex[i], column snakey[i]; segment 0 is the head.
# A missing key reads as 0, which is a wall, so the body ends at the first 0.
@bpf
@map
def snakex() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=10)


@bpf
@map
def snakey() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=10)


@bpf
@map
def state() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=4)


@bpf
@bpfglobal
def key() -> c_int64:
    return c_int64(0)


# pty_write(struct tty_struct *tty, const u8 *buf, size_t c)
@bpf
@section("kprobe/pty_write")
def steer(ctx: struct_pt_regs) -> c_int64:
    global key
    if ctx.dx == 1:
        typed = c_int8(0)
        probe_read_kernel(typed, ctx.si)
        key = typed
    return c_int64(0)


@bpf
@section("kprobe/__x64_sys_getppid")
def tick(ctx: struct_pt_regs) -> c_int64:
    if pid() != state.lookup(3):  # PLAYER
        return c_int64(0)
    if state.lookup(2) != 0:  # GAME_OVER
        return c_int64(0)

    # Move: every segment takes the place of the one ahead of it
    i = 0
    while i < 10 and snakex.lookup(i) != 0 and snakey.lookup(i) != 0:
        i += 1
    i -= 1
    while i > 0:
        snakex.update(i, snakex.lookup(i - 1))
        snakey.update(i, snakey.lookup(i - 1))
        i -= 1

    headx = snakex.lookup(0)
    heady = snakey.lookup(0)
    if key == 65:  # up
        snakex.update(0, headx - 1)
    elif key == 66:  # down
        snakex.update(0, headx + 1)
    elif key == 68:  # left
        snakey.update(0, heady - 1)
    else:  # right
        snakey.update(0, heady + 1)

    # Game over when the head hits a wall ...
    x = snakex.lookup(0)
    y = snakey.lookup(0)
    if x == 0 or x == 11 or y == 0 or y == 49:
        state.update(2, 1)  # GAME_OVER

    # ... or the snake's own body
    i = 1
    while i < 10 and snakex.lookup(i) != 0 and snakey.lookup(i) != 0:
        if x == snakex.lookup(i) and y == snakey.lookup(i):
            state.update(2, 1)  # GAME_OVER
        i += 1

    # Eat: new food somewhere, and the tail grows by one
    if x == state.lookup(0) and y == state.lookup(1):  # FOODX, FOODY
        state.update(0, random() % 10 + 1)
        state.update(1, random() % 10 + 1)
        i = 2
        while i < 10 and snakex.lookup(i) != 0 and snakey.lookup(i) != 0:
            i += 1
        snakex.update(i, snakex.lookup(i - 1))
        snakey.update(i, snakey.lookup(i - 1))

    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


def read(m, k):
    return m.lookup(k) or 0


def render(b):
    body = set()
    for i in range(MAX_LENGTH):
        x, y = read(b["snakex"], i), read(b["snakey"], i)
        if x == 0 or y == 0:
            break
        body.add((x, y))
    food = (read(b["state"], FOODX), read(b["state"], FOODY))

    rows = []
    for x in range(HEIGHT):
        row = []
        for y in range(WIDTH):
            if x == 0 or y == 0 or x == HEIGHT - 1 or y == WIDTH - 1:
                row.append("#")
            elif (x, y) == food:
                row.append("$")
            elif (x, y) in body:
                row.append("@")
            else:
                row.append(" ")
        rows.append("".join(row))
    # One write per frame: the steering probe only looks at one-byte writes
    sys.stdout.write("\033[H" + "\n".join(rows) + "\n")
    sys.stdout.flush()


b = BPF()
b.load()
b.attach_all()

# BEGIN
b["snakex"][0] = 1
b["snakey"][0] = 1
b["snakex"][1] = 1
b["snakey"][1] = 2
b["state"][FOODX] = 4
b["state"][FOODY] = 4
b["state"][PLAYER] = os.getpid()

sys.stdout.write("\033[H\033[2J\033[?25l")  # clear screen, hide cursor
try:
    while True:
        os.getppid()  # interval:ms:120
        render(b)
        if read(b["state"], GAME_OVER):
            print("game over")
            break
        time.sleep(0.12)
except KeyboardInterrupt:
    pass
finally:
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()
    # The keys were echoed but never read: drop them before the shell sees them
    if sys.stdin.isatty():
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
