#include <stdlib.h>

#include "errno.h"
#include "purge.h"
#include "util.h"

long int purge_ratio = -1;

COLD void purge_init(void) {
    char *ratio = secure_getenv("MALLOC_PURGE_RATIO");
    if (ratio) {
        purge_ratio = strtol(ratio, NULL, 10);
    }
}
