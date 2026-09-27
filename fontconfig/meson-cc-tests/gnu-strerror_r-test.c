#define _GNU_SOURCE
#include <string.h>

int
main (void)
{
    char  buf[64];
    char  c = *strerror_r (0, buf, sizeof (buf));
    char *s = strerror_r (0, buf, sizeof (buf));
    return !s || c;
}
