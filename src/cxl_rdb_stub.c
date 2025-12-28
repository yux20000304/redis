#include <stdarg.h>
#include <stdio.h>

int rdbCheckMode = 0;

void rdbCheckError(const char *fmt, ...) {
    (void)fmt;
}

int redis_check_rdb_main(int argc, char **argv, char *pname) {
    (void)argc; (void)argv; (void)pname;
    fprintf(stderr, "redis-check-rdb stub (disabled)\n");
    return 0;
}

int redis_check_aof_main(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "redis-check-aof stub (disabled)\n");
    return 0;
}
