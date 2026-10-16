// test_vmp_header_tu2.c — header-only runtime smoke test (TU 2 of 3):
// a bare VMP.h include that uses none of it. Must compile -Wall -Wextra
// -Werror clean (static-inline internals strip out; the weak vm_exec /
// handle_call definitions coexist with TU 1's strong handle_call at link).
#include "VMP.h"

int vmp_header_tu2_marker(void) { return 1; }
