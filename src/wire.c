#include "wire.h"
#include <string.h>

void wire_stats_init(wire_stats_t *stats){
   if(stats == NULL){
       printf("Initialization failed due to the stats pointer being null\n");
       return;
   }
   memset(stats, 0, sizeof(*stats));
   return;
}

kem_status_t wire_write(uint8_t type, const uint8_t *content, size_t content_len, uint8_t *out, size_t out_cap, size_t *written, wire_stats_t *stats){
    if(content_len <= 0){
        printf("the content pointer was null. Proccess failed :(\n");
        return KEM_ERROR;
    }
    if(out <= 0){
        printf("the out pointer was null. Proccess failed :(\n");
        return KEM_ERROR;
    }
    if(written <= 0){
        printf("the written pointer was null. Proccess failed :(\n");
        return KEM_ERROR;
    }
    if(stats <= 0){
        printf("the stats pointer was null. Proccess failed :(\n");
        return KEM_ERROR;
    }

    size_t total = 1 + 4 + content_len;
    if(total > out_cap) return KEM_ERROR;
    int pos = 0;
    out[pos++] = type;
    out[pos++] = (uint8_t)(content_len >> 24);
    out[pos++] = (uint8_t)(content_len >> 16);
    out[pos++] = (uint8_t)(content_len >> 8);
    out[pos++] = (uint8_t)(content_len >> 0xFF);
    memcpy(out + pos, content, content_len);
    pos += content_len;

    stats->bytes_by_type[type] += total;
    stats->total_bytes += total;
    *written = total;
    return KEM_SUCCESS;
}
