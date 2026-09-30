#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_SIZE 100000
static uint8_t payload[TEST_SIZE];
static uint8_t rcvd[TEST_SIZE];

int transport_testing(void);

int transport_testing(void){
     for(int i = 0; i<TEST_SIZE; i++){
     payload[i] = (uint8_t)(i % 256);
     }
}
