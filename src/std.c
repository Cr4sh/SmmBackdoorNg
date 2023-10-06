#include "common.h"
//--------------------------------------------------------------------------------------
void std_memcpy(void *dst, const void *src, size_t size)
{
    __movsb(dst, src, size);
}
//--------------------------------------------------------------------------------------
size_t std_strlen(const char *str)
{
    if (str)
    {
        size_t i = 0;

        for (; str[i] != '\0'; i++);

        return i;        
    }
 
    return 0;   
}
//--------------------------------------------------------------------------------------
char *std_strcat(char *dst, const char *src)
{
    char *ptr = dst + std_strlen(dst);

    while (*src != '\0')
    {
        // append string
        *ptr++ = *src++;
    }

    // null terminate destination string
    *ptr = '\0';

    return dst;
}
//--------------------------------------------------------------------------------------
// EoF
