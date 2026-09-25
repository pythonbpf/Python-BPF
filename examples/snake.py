# Snake, with the game in the kernel.
#
# A port of bpfsnake (github.com/amiremohamadi/bpfsnake), a bpftrace script.
# The eBPF side keeps the whole game state in maps and runs the game logic:
# steering, moving, collisions, eating and growing. Python only feeds it the
# arrow key and draws what the kernel left in the maps, with pygame.
#
# bpftrace's `interval:ms:120` would be a perf_event program, which pylibbpf
# cannot attach yet. Instead Python drives the clock: every tick it calls
# getppid(), and a kprobe on that syscall, filtered to this process, advances
# the game one step.
#
# The original steered from a kprobe on pty_write, reading the byte a terminal
# echoes for each key. A pygame window has the keyboard instead of the
# terminal, so Python writes the key's code into the `state` map, using the
# same codes: 'A' up, 'B' down, 'C' right, 'D' left.
#
# Needs pygame (pip install pygame). Run from the repository root, keeping
# your display in the environment:
#   sudo -E env PYTHONPATH=. /path/to/python examples/snake.py
# Arrows or WASD steer, Space pauses, R restarts, Esc quits.
# x86_64 only (the syscall name in the kprobe).

import math
import os
from collections import deque
from ctypes import c_int64, c_uint64, c_void_p

import pygame

from pythonbpf import BPF, bpf, bpfglobal, map, section
from pythonbpf.helper import pid, random
from pythonbpf.maps import HashMap

MAX_LENGTH = 32
WIDTH = 30  # columns, walls included
HEIGHT = 20  # rows, walls included
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
    if x == 0 or x == 19 or y == 0 or y == 29:
        state.update(2, 1)  # GAME_OVER

    # ... or the snake's own body
    i = 1
    while i < 32 and snakex.lookup(i) != 0 and snakey.lookup(i) != 0:
        if x == snakex.lookup(i) and y == snakey.lookup(i):
            state.update(2, 1)  # GAME_OVER
        i += 1

    # Eat: new food somewhere inside the walls, and the tail grows by one
    if x == state.lookup(0) and y == state.lookup(1):  # FOODX, FOODY
        state.update(0, random() % 18 + 1)
        state.update(1, random() % 28 + 1)
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

CELL = 28
HUD = 56
OPPOSITE = {UP: DOWN, DOWN: UP, LEFT: RIGHT, RIGHT: LEFT}
KEYS = {
    pygame.K_UP: UP,
    pygame.K_w: UP,
    pygame.K_DOWN: DOWN,
    pygame.K_s: DOWN,
    pygame.K_LEFT: LEFT,
    pygame.K_a: LEFT,
    pygame.K_RIGHT: RIGHT,
    pygame.K_d: RIGHT,
}

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


def read(m, k):
    return m.lookup(k) or 0


def reset(b):
    for i in range(MAX_LENGTH):
        for m in (b["snakex"], b["snakey"]):
            try:
                m.delete_elem(i)
            except Exception:
                pass  # the key was never set
    mid = HEIGHT // 2
    b["snakex"][0], b["snakey"][0] = mid, 4
    b["snakex"][1], b["snakey"][1] = mid, 3
    b["state"][FOODX] = mid
    b["state"][FOODY] = WIDTH // 2
    b["state"][GAME_OVER] = 0
    b["state"][KEY] = RIGHT
    b["state"][PLAYER] = os.getpid()


def snapshot(b):
    body = []
    for i in range(MAX_LENGTH):
        x, y = read(b["snakex"], i), read(b["snakey"], i)
        if x == 0 or y == 0:
            break
        if not body or body[-1] != (x, y):  # a fresh tail sits on the last one
            body.append((x, y))
    food = (read(b["state"], FOODX), read(b["state"], FOODY))
    return body, food, bool(read(b["state"], GAME_OVER))


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


def draw_hud(screen, fonts, body, ticks, paused):
    big, small = fonts
    screen.blit(big.render("bpfsnake", True, TEXT), (16, 12))
    screen.blit(small.render("game logic runs in eBPF", True, MUTED), (160, 22))
    stats = f"length {len(body)}/{MAX_LENGTH}   score {len(body) - 2}   ticks {ticks}"
    s = small.render(stats + ("   paused" if paused else ""), True, ACCENT)
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


b = BPF()
b.load()
b.attach_all()


def main():
    pygame.init()
    pygame.display.set_caption("bpfsnake")
    screen = pygame.display.set_mode((WIDTH * CELL, HUD + HEIGHT * CELL))
    fonts = (
        pygame.font.SysFont("dejavusansmono,monospace", 26, bold=True),
        pygame.font.SysFont("dejavusansmono,monospace", 15),
    )
    clock = pygame.time.Clock()

    reset(b)
    heading, turns = RIGHT, deque(maxlen=3)
    body, food, over = snapshot(b)
    ticks, paused, last_tick = 0, False, pygame.time.get_ticks()

    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return
            if event.type != pygame.KEYDOWN:
                continue
            if event.key == pygame.K_ESCAPE:
                return
            if event.key == pygame.K_SPACE and not over:
                paused = not paused
            elif event.key == pygame.K_r:
                reset(b)
                heading, ticks, paused = RIGHT, 0, False
                turns.clear()
                body, food, over = snapshot(b)
            elif event.key in KEYS:
                turns.append(KEYS[event.key])

        now = pygame.time.get_ticks()
        if not over and not paused and now - last_tick >= TICK_MS:
            last_tick = now
            # One queued turn per tick; reversing onto your own neck is ignored
            while turns:
                turn = turns.popleft()
                if turn not in (heading, OPPOSITE[heading]):
                    heading = turn
                    break
            b["state"][KEY] = heading
            os.getppid()  # interval:ms:120
            ticks += 1
            body, food, over = snapshot(b)

        draw_board(screen)
        draw_food(screen, food, now)
        draw_snake(screen, body)
        draw_hud(screen, fonts, body, ticks, paused)
        if over:
            hint = f"length {len(body)}  ·  R restart  ·  Esc quit"
            draw_overlay(screen, fonts, "game over", hint)
        elif paused:
            draw_overlay(screen, fonts, "paused", "Space resume")
        pygame.display.flip()
        clock.tick(60)


try:
    main()
finally:
    pygame.quit()
