#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Typedef for unsigned 32-bit integer */
typedef uint32_t u4;
/* Typedef for unsigned 8-bit integer */
typedef uint8_t byte;

/* Internal representation of magma substitution blocks */
typedef struct {
    byte k8[16];
    byte k7[16];
    byte k6[16];
    byte k5[16];
    byte k4[16];
    byte k3[16];
    byte k2[16];
    byte k1[16];
} magma_subst_block;

/* Cipher context includes key and preprocessed  substitution block */
typedef struct {
    u4 master_key[8];
    u4 key[8];
    u4 mask[8];
    /* Constant s-boxes -- set up in magma_init(). */
    u4 k87[256], k65[256], k43[256], k21[256];
} magma_ctx;

extern magma_subst_block gost28147_TC26ParamSetZ;
typedef unsigned int word32;



/* Encrypt several full blocks in ECB mode */
void magma_enc_ecb(const byte* key, const byte* inblock, byte* outblock, const int blocks);
/* Decrypt several full blocks in ECB mode */
void magma_dec_ecb(const byte* key, const byte* inblock, byte* outblock, const int blocks);


/* Encrypt several full blocks in CBC mode (ECB based) */
void magma_enc_cbc(const byte* key, const byte* iv, const byte* in, byte* out, const int blocks);
/* Decrypt several full blocks in CBC mode (ECB based) */
void magma_dec_cbc(const byte* key, const byte* in, byte* out, const int blocks);

/* Encrypt several full blocks in CBC mode (ECB^-1 based) */
void magma_enc_cbc_inv(const byte* key, const byte* iv, const byte* in, byte* out, const int blocks);
/* Decrypt several full blocks in CBC mode (ECB^-1 based) */
void magma_dec_cbc_inv(const byte* key, const byte* in, byte* out, const int blocks);

/* Computation of CMAC */
void magma_mac(const byte* key, const byte* indata, byte* outdata, const int blocks);


