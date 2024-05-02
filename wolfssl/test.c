#include <stdio.h>
#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>

void FatalError(const char* message)
{
	printf(message);
	printf("\n");
	exit(1);
}

int main(int argc, char* argv[])
{
	int ret = 0;
	
	printf("wolfSSL_Init()\n");
	
	/* Initialize WolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        FatalError("Failed to initialize WolfSSL");
    }

	printf("wolfSSL_Cleanup()\n");
	wolfSSL_Cleanup();

	printf("Test finished!\n");

	return 0;
}