# Integer Semantics

PythonBPF programs are Python syntax, but the integers in them behave as C integers: the
program runs in the kernel as BPF bytecode, where every value is a fixed-width machine
word. This page describes the rules the compiler applies. They are C's rules, applied to
the `ctypes` types you declare, so a program's arithmetic matches what the equivalent C
program compiled with clang would compute.

```{note}
This is one of the few places where PythonBPF deliberately differs from Python. Python
integers have arbitrary precision and no unsigned types; BPF has neither. The
[divergences from Python](#divergences-from-python) are listed at the end of this page.
```

## Types

An integer's type is the `ctypes` type it was declared with, and the type carries both
a width and a sign:

| Signed | Unsigned | Width |
|---|---|---|
| `c_int8` | `c_uint8` | 8 |
| `c_int16` | `c_uint16` | 16 |
| `c_int32` | `c_uint32` | 32 |
| `c_int64` | `c_uint64` | 64 |

Every declaration site uses these types: local variables initialised with a constructor
call, `@bpfglobal` variables, `@struct` fields, map keys and values, and fields read from
`vmlinux` structures. Helper functions return the type of the kernel's signature, so
`pid()` and `ktime()` are unsigned while `probe_read`-style helpers return a signed
`long`.

```python
count = c_uint32(0)        # a 32-bit unsigned local
delta = c_int64(-1)        # a 64-bit signed local
```

A local assigned without a constructor takes its type from the expression:

```python
now = ktime()              # c_uint64, the helper's return type
total = count + 1          # the type of the addition (see below), held in a 64-bit slot
```

Undeclared locals are always 64 bits wide; the inferred type only decides their sign.
Declare the local with a constructor when a narrower width matters.

### Literals

A literal has the type a C compiler gives it: `int` (32-bit signed) if the value fits,
`long long` (64-bit signed) otherwise. This matters for mixed arithmetic: in
`count / -2` with `count` a `c_uint32`, the literal `-2` is a 32-bit `int`, so the
division happens in `c_uint32` exactly as it would in C.

## Assignment and conversion

Assigning a value to a variable of a different integer type converts it, and the
variable's declared type is what the stored value *is* afterwards:

* **Widening preserves the value.** The conversion looks at the *source*'s sign: an
  unsigned source is zero-extended, a signed source is sign-extended. So a `c_uint32`
  holding `0xFFFFFFFF` stored into a `c_int64` gives `4294967295`, and a `c_int32`
  holding `-1` stored into a `c_uint64` gives `0xFFFFFFFFFFFFFFFF`. This is what C and
  `ctypes` both do.
* **Narrowing truncates.** Only the low bits survive.
* **Same width reinterprets.** A `c_uint32` `0xFFFFFFFF` stored into a `c_int32` reads
  as `-1`.

The same rules apply to explicit conversions written as constructor calls
(`c_int64(count)`), to struct field stores and to `return`.

## Arithmetic

Each binary operation is typed on its own, from its two operands, following C's usual
arithmetic conversions:

1. Operands narrower than 32 bits are promoted to `c_int32`.
2. If both operands have the same sign, the result has the wider width and that sign.
3. If the signs differ, the unsigned type wins when it is at least as wide as the signed
   one; otherwise the signed type wins.

The operation is then performed in that type, and its result has that type. The variable
receiving the result plays no part until the final store. Two consequences worth knowing:

* **Intermediate results wrap at their own width.** `c_uint32(0x80000000) * c_uint32(2)`
  is a `c_uint32` multiplication, so it wraps to `0` before being stored, even if the
  destination is a `c_uint64`. Widen an operand first if you want a 64-bit product.
* **Mixed signs go unsigned.** `c_uint32(10) / c_int32(-2)` is an unsigned division by
  `0xFFFFFFFE`, giving `0`, not `-5`.

The sign of the operation's type selects the instruction for the operations where it
matters:

| Operator | Signed type | Unsigned type |
|---|---|---|
| `/`, `//` | truncating signed division | unsigned division |
| `%` | remainder with the dividend's sign | unsigned remainder |
| `>>` | arithmetic shift (sign bit shifts in) | logical shift (zeros shift in) |
| `<`, `<=`, `>`, `>=` | signed comparison | unsigned comparison |

`+`, `-`, `*`, `<<`, `&`, `|`, `^`, `==` and `!=` produce the same bits for either sign.

Unary minus on an unsigned value follows C too: `-x` is `2^N - x` in the value's type.

## Comparisons

A comparison converts both operands with the same usual arithmetic conversions and then
compares in the resulting type. `c_uint64(10) > c_int64(-1)` is therefore an unsigned
comparison in which `-1` is the largest possible value, and the result is false. The
result of a comparison is `1` or `0`, as in C.

## Divergences from Python

Because the semantics are C's, some Python behaviour does not carry over:

* `/` is integer division; there is no floating-point result.
* `//` and `/` are the same operation, and both truncate toward zero: `-7 // 2` is `-3`,
  where Python gives `-4`.
* `%` takes the sign of the dividend: `-7 % 2` is `-1`, where Python gives `1`.
* Integers have a fixed width and wrap on overflow; there is no arbitrary precision.
* Unsigned types exist, and mixing them with signed values follows C's conversions
  rather than Python's mathematical integers.

The test programs under `tests/passing_tests/signedness/` show each rule with its
expected value, and `tests/c-form/signedness.bpf.c` is the equivalent C program.
