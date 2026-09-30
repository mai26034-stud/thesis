#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_SIZE 100000
static uint8_t payload[TEST_SIZE];
for(int i = 0; i<length(payload); i++){
  payload[i] = (uint8_t)(i % 256);
}
