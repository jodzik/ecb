#ifndef SAFE_C_H_
#define SAFE_C_H_

#include <stdio.h>
#include <string.h>

// #define SAFE_C_LOG_EN__DBG   1
// #define SAFE_C_LOG_EN__INF   1
// #define SAFE_C_LOG_EN__WRN   1
// #define SAFE_C_LOG_EN__ERR   1

#ifdef __linux
#define SLASH '/'
#else
#define SLASH   '\\'
#endif

#define __FILENAME__ (strrchr(__FILE__, SLASH) ? strrchr(__FILE__, SLASH) + 1 : __FILE__)

#define LOG_WITH_PREFIX(prefix, fmt) do { g_safe_c_printf(prefix " %s.%i: " fmt "\n", __FILENAME__, __LINE__); } while (0)
#define LOG_MOCK(fmt) do {} while (0)
#define LOGf_WITH_PREFIX(prefix, fmt, ...) do { g_safe_c_printf(prefix " %s.%i: " fmt "\n", __FILENAME__, __LINE__, __VA_ARGS__); } while (0)

#if SAFE_C_LOG_EN__DBG
    #define DBG_LOG(fmt) LOG_WITH_PREFIX("[DBG]", fmt)
    #define DBG_LOGf(fmt, ...) LOGf_WITH_PREFIX("[DBG]", fmt, __VA_ARGS__)
#else
    #define DBG_LOG(fmt) LOG_MOCK
    #define DBG_LOGf(fmt, ...) LOG_MOCK
#endif

#if SAFE_C_LOG_EN__INF
    #define INF_LOG(fmt) LOG_WITH_PREFIX("[INF]", fmt)
    #define INF_LOGf(fmt, ...) LOGf_WITH_PREFIX("[DBG]", fmt, __VA_ARGS__)
#else
    #define INF_LOG(fmt) LOG_MOCK
    #define INF_LOGf(fmt, ...) LOG_MOCK
#endif

#if SAFE_C_LOG_EN__WRN
    #define WRN_LOG(fmt) LOG_WITH_PREFIX("[WRN]", fmt)
    #define WRN_LOGf(fmt, ...) LOGf_WITH_PREFIX("[WRN]", fmt, __VA_ARGS__)
#else
    #define DBG_LOG(fmt) LOG_MOCK
    #define DBG_LOGf(fmt, ...) LOG_MOCK
#endif

#if SAFE_C_LOG_EN__ERR
    #define ERR_LOG(fmt) LOG_WITH_PREFIX("[ERR]", fmt)
    #define ERR_LOGf(fmt, ...) LOGf_WITH_PREFIX("[ERR]", fmt, __VA_ARGS__)
#else
    #define ERR_LOG(fmt) LOG_MOCK
    #define ERR_LOGf(fmt, ...) LOG_MOCK
#endif

#define __FILENAME__ (strrchr(__FILE__, SLASH) ? strrchr(__FILE__, SLASH) + 1 : __FILE__)

#define TRY(func_expr) do {int _result = func_expr; if (0 != _result) {ERR_LOGf("Fail to call " #func_expr ": %i\n", _result); return _result;}} while (0)
#define TRY_PASS(func_expr) do {int _result = func_expr; if (0 != _result) {ERR_LOGf("Fail to call " #func_expr ": %i\n", _result);}} while (0)
#define TRYf_PASS(func_expr, fmt, ...) do {int _result = func_expr; if (0 != _result) {ERR_LOGf("Fail to call " #func_expr ": %i, " fmt "\n", _result, __VA_ARGS__);}} while (0)
#define TRY_PASS_EX(func_expr) do {int _result = func_expr; if (0 != _result) {ERR_LOGf("Fail to call " #func_expr ": %i\n", _result); rc = _result;}} while (0)
#define TRY_EX(func_expr) do {int _result = func_expr; if (0 != _result) {ERR_LOGf("Fail to call " #func_expr ": %i\n", _result); rc = _result; goto finally;}} while (0)
#define ASSERT(bool_expr, err) do { if (!(bool_expr)) {ERR_LOG("Assertion '" #bool_expr "' failed.\n"); return err;} } while (0)
#define ASSERTm(bool_expr, err, msg) do { if (!(bool_expr)) {ERR_LOG("Assertion '" #bool_expr "' failed | " msg ".\n"); return err;} } while (0)
#define ASSERTf(bool_expr, err, fmt, ...) do { if (!(bool_expr)) {ERR_LOGf("Assertion '" #bool_expr "' failed | " fmt ".\n", __VA_ARGS__); return err;} } while (0)
#define ASSERT_EX(bool_expr, err) do { if (!(bool_expr)) {ERR_LOGf("Assertion '" #bool_expr "' failed.\n"); rc = err; goto finally;} } while (0)

#define UNUSED(var) (void)var

enum {
    ER_NOT_PERM = -1,
    ER_NO_ENT = -2,
    ER_IO = -5,
    ER_INVAL = -22,
    ER_NOT_IMPL = -38,
    ER_OVERFLOW = -75,
    ER_NO_DATA = -61,
    ER_CALIBRATION_FAIL = -200,
    ER_1 = -1000,
    ER_2 = -2000,
    ER_3 = -3000,
    ER_4 = -4000,
    ER_5 = -5000,
    ER_6 = -6000,
    ER_7 = -7000,
    ER_8 = -8000,
    ER_9 = -9000,
    ER_10 = -10000,
    ER_11 = -11000,
    ER_12 = -12000,
    ER_13 = -13000,
    ER_14 = -14000,
    ER_15 = -15000,
    ER_16 = -16000,
    ER_17 = -17000,
    ER_18 = -18000,
    ER_19 = -19000,
    ER_20 = -20000,
    ER_21 = -21000,
    ER_22 = -22000,
    ER_23 = -23000,
    ER_24 = -24000,
    ER_25 = -25000,
    ER_26 = -26000,
    ER_27 = -27000,
    ER_28 = -28000,
    ER_29 = -29000,
    ER_30 = -30000,
    ER_31 = -31000,
    ER_32 = -32000,
    ER_33 = -33000,
    ER_34 = -34000,
    ER_35 = -35000,
    ER_36 = -36000,
    ER_37 = -37000,
    ER_38 = -38000,
    ER_39 = -39000,
    ER_40 = -40000,
};

extern void (*g_safe_c_printf)(char const* fmt, ...);

void safe_c__init(void (*printf_func)(char const* fmt, ...));

#endif // SAFE_C_H_