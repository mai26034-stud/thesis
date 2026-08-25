#ifndef TRANSCRIPT_H
#define TRANSCRIPT_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
typedef struct{
     uint8_t buffer[8192];
     size_t len;
} transcript_t;
#endif
