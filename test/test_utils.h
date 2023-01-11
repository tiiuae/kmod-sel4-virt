#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#define ARRAY_SIZE(arr) (sizeof((arr))/sizeof((arr)[0]))

void _test_assert(bool exp, const char *exp_str, const char *file,
                  unsigned int line, const char *fmt, ...)
                  __attribute__ ((format (printf, 5, 6)));
#define do_assert_fmt(exp, exp_str, fmt, ...) \
  _test_assert((exp), exp_str, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define assert_fmt(exp, fmt, ...) \
  do_assert_fmt((exp), #exp, fmt, ##__VA_ARGS__)

#define assert_true(exp) \
  assert_fmt(exp, "  assert_true failed")

#define assert_cmp(exp, op, suffix,                     \
                   left_str, right_str,                 \
                   left_val, right_val)                 \
do {                                                    \
  do_assert_fmt(exp,                                    \
                NULL,                                   \
                "  assert_" suffix "(%s, %s) failed\n"  \
                "  %#lx " op " %#lx",                   \
                left_str,                               \
                right_str,                              \
                (unsigned long) left_val,               \
                (unsigned long) right_val);             \
} while (0)

#define assert_eq(left, right)      \
do {                                \
  typeof(left) __left = (left);     \
  typeof(right) __right = (right);  \
  assert_cmp(__left == __right,     \
             "==", "eq",            \
             #left, #right,         \
             __left, __right);      \
} while (0)

#define assert_ne(left, right)      \
do {                                \
  typeof(left) __left = (left);     \
  typeof(right) __right = (right);  \
  assert_cmp(__left != __right,     \
             "!=", "ne",            \
             #left, #right,         \
             __left, __right);      \
} while (0)

#define assert_gt(left, right)      \
do {                                \
  typeof(left) __left = (left);     \
  typeof(right) __right = (right);  \
  assert_cmp(__left > __right,      \
             ">", "gt",             \
             #left, #right,         \
             __left, __right);      \
} while (0)

#define assert_lt(left, right)      \
do {                                \
  typeof(left) __left = (left);     \
  typeof(right) __right = (right);  \
  assert_cmp(__left < __right,      \
             "<", "lt",             \
             #left, #right,         \
             __left, __right);      \
} while (0)

#define assert_gte(left, right)     \
do {                                \
  typeof(left) __left = (left);     \
  typeof(right) __right = (right);  \
  assert_cmp(__left >= __right,     \
             ">=", "gte",           \
             #left, #right,         \
             __left, __right);      \
} while (0)

#define assert_lte(left, right)     \
do {                                \
  typeof(left) __left = (left);     \
  typeof(right) __right = (right);  \
  assert_cmp(__left <= __right,     \
             "<=", "lte",           \
             #left, #right,         \
             __left, __right);      \
} while (0)

/* Return 0 on success */
typedef int (*test_function) (void);

struct test_case {
	const char *name;
	test_function test;
};

#define declare_test(func) { #func, func }

/* Return number of failed tests cases, though usually assertion error will
 * simply exit. */
int _run_tests(const struct test_case tests[], const size_t n_tests);
#define run_tests(tests) _run_tests(tests, ARRAY_SIZE(tests))

#endif /* TEST_UTILS_H */
