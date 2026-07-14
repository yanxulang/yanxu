#include "yanxu.h"
#include <stdio.h>

int main(void) {
    YanxuEngine *engine = yanxu_engine_new();
    if (engine == NULL) {
        fputs("cannot create Yanxu engine\n", stderr);
        return 1;
    }

    char *result = yanxu_engine_run(engine, "异 法 求（）：数 则 归 42；终 言 候 求（）；");
    if (result == NULL) {
        yanxu_engine_free(engine);
        return 1;
    }
    puts(result);
    yanxu_string_free(result);
    yanxu_engine_free(engine);
    return 0;
}
