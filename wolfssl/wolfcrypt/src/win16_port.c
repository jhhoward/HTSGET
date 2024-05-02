#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <windows.h>

/* RNG CODE */
/* TODO: Implement real RNG */
static word32 gCounter;
word32 hw_rand(void)
{
    /* #warning Must implement your own random source */
    ++gCounter;
    return GetTickCount() ^ gCounter;
}

word32 my_rng_seed_gen(void)
{
    return hw_rand();
}

int my_rng_gen_block(unsigned char* output, unsigned int sz)
{
    unsigned long i = 0;
    unsigned long randReturnSize = sizeof(CUSTOM_RAND_TYPE);

    while (i < sz)
    {
        /* If not aligned or there is odd/remainder */
        if((i + randReturnSize) > sz ||
            ((unsigned long)&output[i] % randReturnSize) != 0 ) {
            /* Single byte at a time */
            output[i++] = (unsigned char)my_rng_seed_gen();
        }
        else {
            /* Use native 8, 16, 32 or 64 copy instruction */
            *((CUSTOM_RAND_TYPE*)&output[i]) = my_rng_seed_gen();
            i += randReturnSize;
        }
    }

    return 0;
}

#pragma off(unreferenced)
BOOL far pascal LibMain(
    HANDLE hInstance,
    WORD wDataSegment,
    WORD wHeapSize,
    LPSTR lpszCmdLine
) {
#pragma on(unreferenced)
    if (wHeapSize > 0) {
        UnlockData(0);
    }
    return(TRUE);
}

#pragma off(unreferenced)
int far pascal WEP(int nParameter)
#pragma on(unreferenced)
{
    return(1);
}
