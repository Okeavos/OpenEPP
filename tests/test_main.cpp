#include "test_framework.h"

#include "common/log.h"

int main() {
    sec::log::set_console(false);
    for (const auto& t : sec_test::registry()) {
        const int before = sec_test::failures();
        std::printf("[ RUN  ] %s\n", t.name);
        t.fn();
        std::printf("[ %s ] %s\n", sec_test::failures() == before ? " OK " : "FAIL", t.name);
    }
    std::printf("\n%d checks, %d failure(s)\n", sec_test::checks(), sec_test::failures());
    return sec_test::failures() == 0 ? 0 : 1;
}
