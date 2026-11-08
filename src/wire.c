#include "wire.h"
#include <string.h>
#include <stdio.h>

void wire_stats_init(wire_stats_t *stats){
   if(stats == NULL){
       printf("Initialization failed due to the stats pointer being null\n");
       return;
   }
   memset(stats, 0, sizeof(*stats));
   return;
}

kem_status_t wire_write(uint8_t type, const uint8_t *content, size_t content_len, uint8_t *out, size_t out_cap, size_t *written, wire_stats_t *stats){
    if(out == NULL || written == NULL) return KEM_ERROR;
    if(content == NULL && content_len > 0) return KEM_ERROR;

    size_t total = 1 + 4 + content_len;
    if(total > out_cap) return KEM_ERROR;
    size_t pos = 0;
    out[pos++] = type;
    out[pos++] = (uint8_t)(content_len >> 24);
    out[pos++] = (uint8_t)(content_len >> 16);
    out[pos++] = (uint8_t)(content_len >> 8);
    out[pos++] = (uint8_t)(content_len & 0xFF);
    if(content_len > 0) memcpy(out + pos, content, content_len);
    pos += content_len;

    if(stats != NULL){
        stats->bytes_by_type[type] += total;
        stats->total_bytes += total;
    }
    *written = total;
    return KEM_SUCCESS;
}

kem_status_t wire_read(const uint8_t *in, size_t in_len, uint8_t *type_out, const uint8_t **content_out, size_t *content_len_out, size_t *consumed){
    if(in == NULL || type_out == NULL || content_out == NULL || content_len_out == NULL || consumed == NULL) return KEM_ERROR;
    if(in_len < 5){
        printf("Insufficient space! Can't Proceed :(\n");
        return KEM_ERROR;
    }
    *type_out = in[0];
    size_t content_len = ((size_t)in[1] << 24) | ((size_t)in[2] << 16) | ((size_t)in[3] << 8) | ((size_t)in[4]);
    if(in_len < 5 + content_len) return KEM_ERROR;

   *content_out = in + 5;
   *content_len_out = content_len;
   *consumed = 5 + content_len;
   return KEM_SUCCESS;
}
