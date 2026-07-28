#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <oqs/oqs.h>
#include <stdio.h>
int main(){
     WC_RNG rng;
     int testingVar = wc_InitRng(&rng);
     if(testingVar != 0){
         printf("Error!\n");
         return 1; 
     }else{ 
        printf("Success!\n");
     }
     wc_FreeRng(&rng);
     const char* testtt= OQS_version();
     printf("%s\n", testtt);
     return 0;
}