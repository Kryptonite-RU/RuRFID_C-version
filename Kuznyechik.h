#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef uint64_t U64;
typedef uint8_t byte;

/* Encrypt several full blocks in ECB mode */
void kuznyechik_enc_ecb(const byte* key, const byte* inblock, byte* outblock, int blocks);
/* Decrypt several full blocks in ECB mode */
void kuznyechik_dec_ecb(const byte* key, const byte* inblock, byte* outblock, int blocks);


/* Encrypt several full blocks in CBC mode (ECB based) */
void kuznyechik_enc_cbc(const byte* key, const byte* iv, const byte* in, byte* out, int blocks);
/* Decrypt several full blocks in CBC mode (ECB based) */
void kuznyechik_dec_cbc(const byte* key, const byte* in, byte* out, int blocks);

/* Encrypt several full blocks in CBC mode (ECB^-1 based) */
void kuznyechik_enc_cbc_inv(const byte* key, const byte* iv, const byte* in, byte* out, int blocks);
/* Decrypt several full blocks in CBC mode (ECB^-1 based) */
void kuznyechik_dec_cbc_inv(const byte* key, const byte* in, byte* out, int blocks);

/* Computation of CMAC */
void kuznyechik_mac(const byte* key, const byte* indata, byte* outdata, const int blocks);