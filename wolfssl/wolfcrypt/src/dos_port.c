#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <stdio.h>

unsigned long LFSR (){
	static unsigned long x = 1;  /*Register must be unsigned so right
									shift works properly.*/
	/*Register should be initialized with some random value.*/
	x = ((((x >> 31)  /*Shift the 32nd bit to the first
									bit*/
			 ^ (x >> 6)    /*XOR it with the seventh bit*/
			 ^ (x >> 4)    /*XOR it with the fifth bit*/
			 ^ (x >> 2)    /*XOR it with the third bit*/
			 ^ (x >> 1)    /*XOR it with the second bit*/
			 ^ x)          /*and XOR it with the first bit.*/
			 & 0x0000001)         /*Strip all the other bits off and*/
			 <<31)                /*move it back to the 32nd bit.*/
			 | (x >> 1);   /*Or with the register shifted
									right.*/
	return x & 0x00000001;   /*Return the first bit.*/
}

long my_rng_seed_gen(void)
{
	long result = LFSR();
	result = 0x11111111;  // LOL
	//printf("Random: %ld\n", result);
	return result;
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

#if 0
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

#endif