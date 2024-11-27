#include "safe_c.h"

#include <stdlib.h>

void (*g_safe_c_printf)(char const* fmt, ...) = NULL;

void safe_c__init(void (*printf_func)(char const* fmt, ...)) {
    g_safe_c_printf = printf_func;
}
