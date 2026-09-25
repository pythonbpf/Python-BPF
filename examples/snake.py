# Snake, with the game in the kernel.
#
# A port of bpfsnake (github.com/amiremohamadi/bpfsnake), a bpftrace script.
# The eBPF side keeps the whole game state in maps and runs the game logic:
# steering, moving, collisions, eating and growing. Python only feeds it the
# arrow key and draws what the kernel left in the maps, in a pygame window or,
# with --terminal, in the terminal.
#
# bpftrace's `interval:ms:120` would be a perf_event program, which pylibbpf
# cannot attach yet. Instead Python drives the clock: every tick it calls
# getppid(), and a kprobe on that syscall, filtered to this process, advances
# the game one step.
#
# The original steered from a kprobe on pty_write, reading the byte a terminal
# echoes for each key. That cannot see keys typed into a pygame window, so
# Python writes the key's code into the `state` map instead, in both modes,
# using the original's codes: 'A' up, 'B' down, 'C' right, 'D' left.
#
# Run from the repository root:
#   sudo -E env PYTHONPATH=. /path/to/python examples/snake.py     # pygame
#   sudo env PYTHONPATH=. /path/to/python examples/snake.py --terminal
# The pygame window needs pygame (pip install pygame), and -E keeps your display
# in the environment. The terminal draws the original's board, and like the
# original the game ends when the snake dies.
# Arrows or WASD steer, Space pauses, R restarts, Esc or Q quits.
# x86_64 only (the syscall name in the kprobe).

import argparse
import math
import os
import select
import sys
import termios
import time
import tty
from collections import deque
from ctypes import c_int64, c_uint64, c_void_p

from pythonbpf import BPF, bpf, bpfglobal, map, section
from pythonbpf.helper import pid, random
from pythonbpf.maps import HashMap

MAX_LENGTH = 32
WIDTH = 50  # columns, walls included
HEIGHT = 12  # rows, walls included
TICK_MS = 120

# Slots in the `state` map. The eBPF function spells them as literals: module
# constants are not visible inside it.
FOODX, FOODY, GAME_OVER, PLAYER, KEY = 0, 1, 2, 3, 4
UP, DOWN, RIGHT, LEFT = 65, 66, 67, 68


# Body segment i sits at row snakex[i], column snakey[i]; segment 0 is the head.
# A missing key reads as 0, which is a wall, so the body ends at the first 0.
@bpf
@map
def snakex() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=32)


@bpf
@map
def snakey() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=32)


@bpf
@map
def state() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=5)


@bpf
@section("kprobe/__x64_sys_getppid")
def tick(ctx: c_void_p) -> c_int64:
    if pid() != state.lookup(3):  # PLAYER
        return c_int64(0)
    if state.lookup(2) != 0:  # GAME_OVER
        return c_int64(0)

    # Move: every segment takes the place of the one ahead of it
    i = 0
    while i < 32 and snakex.lookup(i) != 0 and snakey.lookup(i) != 0:
        i += 1
    i -= 1
    while i > 0:
        snakex.update(i, snakex.lookup(i - 1))
        snakey.update(i, snakey.lookup(i - 1))
        i -= 1

    key = state.lookup(4)  # KEY
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
    while i < 32 and snakex.lookup(i) != 0 and snakey.lookup(i) != 0:
        if x == snakex.lookup(i) and y == snakey.lookup(i):
            state.update(2, 1)  # GAME_OVER
        i += 1

    # Eat: new food somewhere inside the walls, and the tail grows by one
    if x == state.lookup(0) and y == state.lookup(1):  # FOODX, FOODY
        state.update(0, random() % 10 + 1)
        state.update(1, random() % 48 + 1)
        i = 2
        while i < 32 and snakex.lookup(i) != 0 and snakey.lookup(i) != 0:
            i += 1
        snakex.update(i, snakex.lookup(i - 1))
        snakey.update(i, snakey.lookup(i - 1))

    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# ---------------------------------------------------------------- userspace

OPPOSITE = {UP: DOWN, DOWN: UP, LEFT: RIGHT, RIGHT: LEFT}


def read(m, k):
    return m.lookup(k) or 0


class Game:
    """The userspace half: queue turns, drive the kernel's tick, read it back."""

    def __init__(self, b):
        self.b = b
        self.restart()

    def restart(self):
        b = self.b
        for i in range(MAX_LENGTH):
            for m in (b["snakex"], b["snakey"]):
                try:
                    m.delete_elem(i)
                except Exception:
                    pass  # the key was never set
        # BEGIN, as in the original
        b["snakex"][0], b["snakey"][0] = 1, 1
        b["snakex"][1], b["snakey"][1] = 1, 2
        b["state"][FOODX], b["state"][FOODY] = 4, 4
        b["state"][GAME_OVER] = 0
        b["state"][KEY] = RIGHT
        b["state"][PLAYER] = os.getpid()
        self.heading, self.turns = RIGHT, deque(maxlen=3)
        self.ticks, self.paused = 0, False
        self.last_tick = time.monotonic()
        self.snapshot()

    def turn(self, code):
        self.turns.append(code)

    def toggle_pause(self):
        if not self.over:
            self.paused = not self.paused

    def due(self):
        return time.monotonic() - self.last_tick >= TICK_MS / 1000

    def tick(self):
        """One step of the game, run by the kernel."""
        self.last_tick = time.monotonic()
        if self.over or self.paused:
            return
        # One queued turn per tick; reversing onto your own neck is ignored
        while self.turns:
            turn = self.turns.popleft()
            if turn not in (self.heading, OPPOSITE[self.heading]):
                self.heading = turn
                break
        self.b["state"][KEY] = self.heading
        os.getppid()  # interval:ms:120
        self.ticks += 1
        self.snapshot()

    def snapshot(self):
        b, body = self.b, []
        for i in range(MAX_LENGTH):
            x, y = read(b["snakex"], i), read(b["snakey"], i)
            if x == 0 or y == 0:
                break
            if not body or body[-1] != (x, y):  # a fresh tail sits on the last one
                body.append((x, y))
        self.body = body
        self.food = (read(b["state"], FOODX), read(b["state"], FOODY))
        self.over = bool(read(b["state"], GAME_OVER))

    def status(self):
        n = len(self.body)
        return f"length {n}/{MAX_LENGTH}   score {n - 2}   ticks {self.ticks}"


# ----------------------------------------------------------------- terminal


# Bytes a terminal sends: an arrow is ESC [ A..D (or ESC O A..D), and its last
# byte happens to be the code the kernel expects.
T_KEYS = {b"w": UP, b"s": DOWN, b"a": LEFT, b"d": RIGHT}


def terminal_frame(game):
    """The board exactly as the bpftrace script prints it."""
    body = set(game.body)
    rows = []
    for x in range(HEIGHT):
        row = []
        for y in range(WIDTH):
            if x == 0 or y == 0 or x == HEIGHT - 1 or y == WIDTH - 1:
                row.append("#")
            elif (x, y) == game.food:
                row.append("$")
            elif (x, y) in body:
                row.append("@")
            else:
                row.append(" ")
        rows.append("".join(row) + "\n")
    return "\033[H" + "".join(rows)  # move cursor to top left


def terminal_keys(data, game):
    """Apply a burst of bytes read from the terminal. False means quit."""
    i = 0
    while i < len(data):
        ch = data[i : i + 1]
        if ch == b"\x1b" and data[i + 1 : i + 2] in (b"[", b"O"):
            code = data[i + 2 : i + 3]
            if code in (b"A", b"B", b"C", b"D"):
                game.turn(code[0])
            i += 3
            continue
        ch = ch.lower()
        if ch in (b"q", b"\x03"):
            return False
        if ch == b" ":
            game.toggle_pause()
        elif ch == b"r":
            game.restart()
        elif ch in T_KEYS:
            game.turn(T_KEYS[ch])
        i += 1
    return True


def run_terminal(game):
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    out = sys.stdout
    try:
        tty.setcbreak(fd)  # keys arrive at once and are not echoed
        out.write("\033[H\033[2J")  # clear screen
        while True:
            out.write(terminal_frame(game))
            out.flush()
            if game.over:
                return  # exit(), as in the original
            wait = max(0.0, TICK_MS / 1000 - (time.monotonic() - game.last_tick))
            if select.select([fd], [], [], wait)[0]:
                if not terminal_keys(os.read(fd, 64), game):
                    return
            if game.due():
                game.tick()
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, saved)


# ------------------------------------------------------------------- pygame

CELL = 24
HUD = 56

BG = (15, 23, 42)
TILE = (22, 32, 54)
WALL = (51, 65, 85)
WALL_EDGE = (71, 85, 105)
HEAD = (74, 222, 128)
TAIL = (21, 128, 61)
FOOD = (244, 63, 94)
LEAF = (132, 204, 22)
TEXT = (226, 232, 240)
MUTED = (148, 163, 184)
ACCENT = (56, 189, 248)


def cell_rect(x, y, inset=0):
    return pygame.Rect(
        y * CELL + inset, HUD + x * CELL + inset, CELL - 2 * inset, CELL - 2 * inset
    )


def mix(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def draw_board(screen):
    screen.fill(BG)
    for x in range(HEIGHT):
        for y in range(WIDTH):
            if x in (0, HEIGHT - 1) or y in (0, WIDTH - 1):
                pygame.draw.rect(screen, WALL, cell_rect(x, y, 1), border_radius=5)
                pygame.draw.rect(
                    screen, WALL_EDGE, cell_rect(x, y, 1), width=1, border_radius=5
                )
            elif (x + y) % 2:
                pygame.draw.rect(screen, TILE, cell_rect(x, y))


def draw_food(screen, food, now):
    pulse = (math.sin(now / 180) + 1) / 2
    r = cell_rect(*food)
    glow = pygame.Surface((CELL * 2, CELL * 2), pygame.SRCALPHA)
    pygame.draw.circle(
        glow, (*FOOD, int(40 + 50 * pulse)), (CELL, CELL), int(CELL * 0.7 + 4 * pulse)
    )
    screen.blit(glow, (r.centerx - CELL, r.centery - CELL))
    pygame.draw.circle(screen, FOOD, r.center, CELL // 2 - 4)
    pygame.draw.circle(screen, (255, 160, 180), (r.centerx - 3, r.centery - 3), 3)
    pygame.draw.ellipse(screen, LEAF, (r.centerx, r.top + 1, 8, 5))


def draw_snake(screen, body):
    n = len(body)
    for i in range(n - 1, -1, -1):
        color = mix(HEAD, TAIL, i / max(n - 1, 1))
        # Bridge to the segment behind so the body reads as one piece
        if i + 1 < n:
            a, b = cell_rect(*body[i], 3), cell_rect(*body[i + 1], 3)
            pygame.draw.rect(screen, color, a.union(b), border_radius=8)
        inset = 2 if i == 0 else 3
        pygame.draw.rect(screen, color, cell_rect(*body[i], inset), border_radius=8)
    if n >= 2:
        (hx, hy), (nx, ny) = body[0], body[1]
        dx, dy = hx - nx, hy - ny  # rows, columns
    else:
        dx, dy = 0, 1
    cx, cy = cell_rect(*body[0]).center
    for side in (-1, 1):
        # Eyes sit ahead of centre, spread across the direction of travel.
        # Screen x follows columns (dy) and screen y follows rows (dx).
        ex = cx + dy * 3 + dx * side * 5
        ey = cy + dx * 3 + dy * side * 5
        pygame.draw.circle(screen, (255, 255, 255), (ex, ey), 4)
        pygame.draw.circle(screen, BG, (ex + dy, ey + dx), 2)


def draw_hud(screen, fonts, game):
    big, small = fonts
    screen.blit(big.render("bpfsnake", True, TEXT), (16, 12))
    screen.blit(small.render("game logic runs in eBPF", True, MUTED), (160, 22))
    s = small.render(game.status(), True, ACCENT)
    screen.blit(s, (WIDTH * CELL - s.get_width() - 16, 22))


def draw_overlay(screen, fonts, title, hint):
    big, small = fonts
    shade = pygame.Surface(screen.get_size(), pygame.SRCALPHA)
    shade.fill((2, 6, 23, 170))
    screen.blit(shade, (0, 0))
    t = big.render(title, True, TEXT)
    h = small.render(hint, True, MUTED)
    cx, cy = screen.get_width() // 2, screen.get_height() // 2
    screen.blit(t, (cx - t.get_width() // 2, cy - 30))
    screen.blit(h, (cx - h.get_width() // 2, cy + 12))


def run_pygame(game):
    pygame.init()
    pygame.display.set_caption("bpfsnake")
    screen = pygame.display.set_mode((WIDTH * CELL, HUD + HEIGHT * CELL))
    fonts = (
        pygame.font.SysFont("dejavusansmono,monospace", 26, bold=True),
        pygame.font.SysFont("dejavusansmono,monospace", 15),
    )
    keys = {
        pygame.K_UP: UP,
        pygame.K_w: UP,
        pygame.K_DOWN: DOWN,
        pygame.K_s: DOWN,
        pygame.K_LEFT: LEFT,
        pygame.K_a: LEFT,
        pygame.K_RIGHT: RIGHT,
        pygame.K_d: RIGHT,
    }
    clock = pygame.time.Clock()
    try:
        while True:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    return
                if event.type != pygame.KEYDOWN:
                    continue
                if event.key in (pygame.K_ESCAPE, pygame.K_q):
                    return
                if event.key == pygame.K_SPACE:
                    game.toggle_pause()
                elif event.key == pygame.K_r:
                    game.restart()
                elif event.key in keys:
                    game.turn(keys[event.key])
            if game.due():
                game.tick()

            draw_board(screen)
            draw_food(screen, game.food, pygame.time.get_ticks())
            draw_snake(screen, game.body)
            draw_hud(screen, fonts, game)
            if game.over:
                hint = f"length {len(game.body)}  ·  R restart  ·  Esc quit"
                draw_overlay(screen, fonts, "game over", hint)
            elif game.paused:
                draw_overlay(screen, fonts, "paused", "Space resume")
            pygame.display.flip()
            clock.tick(60)
    finally:
        pygame.quit()


parser = argparse.ArgumentParser(description="Snake, with the game in eBPF.")
parser.add_argument(
    "--terminal",
    action="store_true",
    help="draw in this terminal instead of a pygame window (no pygame needed)",
)
args = parser.parse_args()
if not args.terminal:
    try:
        import pygame
    except ImportError:
        sys.exit("snake.py: pygame is not installed; pip install pygame, or --terminal")

b = BPF()
b.load()
b.attach_all()

try:
    if args.terminal:
        run_terminal(Game(b))
    else:
        run_pygame(Game(b))
except KeyboardInterrupt:
    pass
