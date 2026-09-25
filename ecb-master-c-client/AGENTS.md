 ## Code Rules
- **Safety:** Validate input, avoid undefined behavior. No guesswork.
- **Style:** Strictly follow the style of the file being edited.
- **Surgical:** Minimal diff. Do not touch working code unless necessary.
- **Honesty:** Unsure about an API or behavior? Ask. Do not guess.
- **Minimalism:** No unnecessary abstractions, duplication, or obvious comments.

## Communication
- Reply in the same language as the question.
- Be concise.
- Be brief.
- When multiple solutions exist, describe them with trade-offs and recommend one with justification.
- Back up claims with real standards and documentation.

---

## Overview

This repository is ECB master c implementation with tests.

See `../README.md` for protocol description.

## Build

To build the project use: `build.sh`

---

## Code Style & Conventions

### General Rules (C and C++)

- **Line length:** maximum 120 characters.
- **Indentation:** 4 spaces (tabs forbidden).
- **Braces:** K&R style (opening brace on the same line line).
- **Naming:**
- - **Functions:** `snake_case`.
- - **Variables:** `snake_case`.
- - **Files:** `snake_case`.
- - **Constants:** UPPERSNAKE_CASE.
- - **struct/enum types:** CamelCase.
- **assert() forbidden** — use `safe-c` library macros: `ASSERT*`, `TRY*`.
- **Comments:** in Russian or English, matching the language of the edited file.
- **Public API:** document in Doxygen format.
- **Build warnings** are not allowed.
- In `==`/`!=` comparisons, put the constant on the left (Yoda style).
- Functions return `int` (0 = success, otherwise — error code from `safe-c`).
- Integer types — generally use fixed types as `uint8_t`, `int_32_t` etc.
- Strings: `strlcpy` instead of `strncpy`/`strcpy`; `memmove` instead of `memcpy` for overlapping buffers.
- `goto` — only for a single exit point, label `finally`.
- `switch` always has a `default` case, with an explicit `break` or a comment explaining fallthrough.
- Function parameters — if declaration not fit in 120 symbols - each parameter on a new line.
- Use explicit `struct`/`enum` keywords in parameter/variable declarations.
- VLA and `alloca()` forbidden.
- Global variables prefixed with `g_`.
- Exported variables prefixed with `e_`, include exported with macros such as `ZBUS_CHAN_DECLARE` etc.
- Blank lines without spaces.

### Writing C Code

Always use the safe-c framework (`./safe-c/`) macros when writing C code:

1. Every function that uses `safe-c` macros must declare the `rc` variable and
   return it at the end under the label finally.
2. Prefer `ASSERT`/`ASSERTf` over explicit condition checking with `goto` on failure.
3. Prefer `TRY`/`TRYf` checking the return value via if and going to goto finally
4. Declare loop variables inside the loop: `for (int i = 0; i < size; i++)`.
5. Return values must be from the `ErrorCodes` enum. If none fits, add new.
6. Check input parameters in public functions(non static, declared in header).
   Parameters that cannot be NULL declare with the `__nonnull` attribute instead of the runtime check.
7. Name private(static) functions with leading `_`.
8. Use const in all declarations where it is possible (if variable/parameter doesn't mutable, etc.).
9. Place types and constants in .c files if its doesn't needed in public API.
10. Place constants near with its use, e.g. if constant used only in one function - declare constant in it function.

Structure of `.c` file:
1. includes.
2. local typedefs.
3. private function declarations(if needed).
4. constants.
5. global variables (including declared with macros such as `BT_GATT_SERVICE_DEFINE` and etc.).
6. private(static) functions.
7. public functions.

Example:

```c
int foo(int32_t const arg, char* const output, size_t const output_size)
{
    int rc = 0;
    int check = 0;

    ASSERTf(42 != arg, ER_INVAL, "Invalid arg value: %d", arg);
    ASSERTf(NULL != output, ER_INVAL, "Invalid output ptr");

    TRY(some_other_function_from_project(arg));

    check = snprintf(output, output_size, "The arg is %d\n", arg);
    ASSERTf(check > 0, ER_1, "snprintf() failed: %d", check);

    LOG_INF("Object create with name: %s", name);
    LOG_ERR("Object create failed.");

 finally:

    return ret;
}
```

Bad vs. good pattern:

```c
// Bad:
if (foo)
{
    LOG_ERR("foo check failed: %d", foo);
    goto finally;
}

// Good:
ASSERTf(foo, ER_1, "foo check failed: %d", foo);
```
