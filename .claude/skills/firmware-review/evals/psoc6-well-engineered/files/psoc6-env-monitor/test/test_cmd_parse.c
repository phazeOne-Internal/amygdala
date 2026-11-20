#include <assert.h>
#include <string.h>
#include "../source/app.h"
int main(void)
{
    uint32_t v = 0;
    assert(cmd_parse((const uint8_t *)"interval=60000", 14, &v) == 0 && v == 60000u);
    assert(cmd_parse((const uint8_t *)"interval=1", 10, &v) != 0);            /* below min */
    assert(cmd_parse((const uint8_t *)"interval=99999999", 17, &v) != 0);     /* too long */
    assert(cmd_parse((const uint8_t *)"interval=12a45", 14, &v) != 0);
    assert(cmd_parse((const uint8_t *)"interval=", 9, &v) != 0);
    return 0;
}
