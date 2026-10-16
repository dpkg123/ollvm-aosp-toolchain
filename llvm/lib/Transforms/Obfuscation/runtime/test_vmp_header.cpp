// test_vmp_header.cpp — header-only runtime smoke test (TU 3 of 3):
// VMP.h must be includable and usable from C++.
#include "VMP.h"

extern "C" int vmp_header_cpp_smoke(void) {
    // RET const 7
    const unsigned char b[] = {0x0A, 0, 0, 8, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0};
    return vm_exec(b, sizeof b, 0, 0) == 7 ? 0 : 1;
}
