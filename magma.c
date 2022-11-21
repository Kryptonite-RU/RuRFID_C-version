#define _CRT_SECURE_NO_WARNINGS
#include "magma.h"


/* 1.2.643.7.1.2.5.1.1 */
magma_subst_block gost28147_TC26ParamSetZ = {
    {0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc,
     0xb, 0x2}
    ,
    {0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa,
     0x3, 0x7}
    ,
    {0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3,
     0xe, 0x0}
    ,
    {0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4,
     0x2, 0xc}
    ,
    {0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe,
     0x9, 0xb}
    ,
    {0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9,
     0x6, 0x0}
    ,
    {0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd,
     0x0, 0xf}
    ,
    {0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3,
     0xf, 0x1}
};



/* Set key into context without key mask */
void magma_key_nomask(magma_ctx* c, const byte* k);
/* Intermediate function used for calculate hash */
void magma_enc_with_key(magma_ctx* c, const byte* key, const byte* inblock, byte* outblock);



/* Initialization of magma_ctx subst blocks*/
void kboxinit(magma_ctx* c, const magma_subst_block* b)
{
    int i;

    for (i = 0; i < 256; i++) {
        c->k87[i] = (word32)(b->k8[i >> 4] << 4 | b->k7[i & 15]) << 24;
        c->k65[i] = (b->k6[i >> 4] << 4 | b->k5[i & 15]) << 16;
        c->k43[i] = (b->k4[i >> 4] << 4 | b->k3[i & 15]) << 8;
        c->k21[i] = b->k2[i >> 4] << 4 | b->k1[i & 15];

    }
}

/* Part of magma 28147 algorithm moved into separate function */
static word32 f(magma_ctx* c, word32 x)
{
    x = c->k87[x >> 24 & 255] | c->k65[x >> 16 & 255] |
        c->k43[x >> 8 & 255] | c->k21[x & 255];
    /* Rotate left 11 bits */
    return x << 11 | x >> (32 - 11);
}

/* Low-level encryption routine - encrypts one 64 bit block*/
void magmacrypt(magma_ctx* c, const byte* in, byte* out)
{
    register word32 n1, n2;
    n1 = in[7 - 0] | (in[7 - 1] << 8) | (in[7 - 2] << 16) | ((word32)in[7 - 3] << 24);
    n2 = in[7 - 4] | (in[7 - 5] << 8) | (in[7 - 6] << 16) | ((word32)in[7 - 7] << 24);

    n2 ^= f(c, n1 + c->key[0] + c->mask[0]);
    n1 ^= f(c, n2 + c->key[1] + c->mask[1]);
    n2 ^= f(c, n1 + c->key[2] + c->mask[2]);
    n1 ^= f(c, n2 + c->key[3] + c->mask[3]);
    n2 ^= f(c, n1 + c->key[4] + c->mask[4]);
    n1 ^= f(c, n2 + c->key[5] + c->mask[5]);
    n2 ^= f(c, n1 + c->key[6] + c->mask[6]);
    n1 ^= f(c, n2 + c->key[7] + c->mask[7]);

    n2 ^= f(c, n1 + c->key[0] + c->mask[0]);
    n1 ^= f(c, n2 + c->key[1] + c->mask[1]);
    n2 ^= f(c, n1 + c->key[2] + c->mask[2]);
    n1 ^= f(c, n2 + c->key[3] + c->mask[3]);
    n2 ^= f(c, n1 + c->key[4] + c->mask[4]);
    n1 ^= f(c, n2 + c->key[5] + c->mask[5]);
    n2 ^= f(c, n1 + c->key[6] + c->mask[6]);
    n1 ^= f(c, n2 + c->key[7] + c->mask[7]);

    n2 ^= f(c, n1 + c->key[0] + c->mask[0]);
    n1 ^= f(c, n2 + c->key[1] + c->mask[1]);
    n2 ^= f(c, n1 + c->key[2] + c->mask[2]);
    n1 ^= f(c, n2 + c->key[3] + c->mask[3]);
    n2 ^= f(c, n1 + c->key[4] + c->mask[4]);
    n1 ^= f(c, n2 + c->key[5] + c->mask[5]);
    n2 ^= f(c, n1 + c->key[6] + c->mask[6]);
    n1 ^= f(c, n2 + c->key[7] + c->mask[7]);

    n2 ^= f(c, n1 + c->key[7] + c->mask[7]);
    n1 ^= f(c, n2 + c->key[6] + c->mask[6]);
    n2 ^= f(c, n1 + c->key[5] + c->mask[5]);
    n1 ^= f(c, n2 + c->key[4] + c->mask[4]);
    n2 ^= f(c, n1 + c->key[3] + c->mask[3]);
    n1 ^= f(c, n2 + c->key[2] + c->mask[2]);
    n2 ^= f(c, n1 + c->key[1] + c->mask[1]);
    n1 ^= f(c, n2 + c->key[0] + c->mask[0]);

    out[7 - 0] = (byte)(n2 & 0xff);
    out[7 - 1] = (byte)((n2 >> 8) & 0xff);
    out[7 - 2] = (byte)((n2 >> 16) & 0xff);
    out[7 - 3] = (byte)(n2 >> 24);
    out[7 - 4] = (byte)(n1 & 0xff);
    out[7 - 5] = (byte)((n1 >> 8) & 0xff);
    out[7 - 6] = (byte)((n1 >> 16) & 0xff);
    out[7 - 7] = (byte)(n1 >> 24);
}

/* Low-level decryption routine. Decrypts one 64-bit block */
void magmadecrypt(magma_ctx* c, const byte* in, byte* out)
{
    register word32 n1, n2;
    n1 = in[7 - 0] | (in[7 - 1] << 8) | (in[7 - 2] << 16) | ((word32)in[7 - 3] << 24);
    n2 = in[7 - 4] | (in[7 - 5] << 8) | (in[7 - 6] << 16) | ((word32)in[7 - 7] << 24);

    n2 ^= f(c, n1 + c->key[0] + c->mask[0]);
    n1 ^= f(c, n2 + c->key[1] + c->mask[1]);
    n2 ^= f(c, n1 + c->key[2] + c->mask[2]);
    n1 ^= f(c, n2 + c->key[3] + c->mask[3]);
    n2 ^= f(c, n1 + c->key[4] + c->mask[4]);
    n1 ^= f(c, n2 + c->key[5] + c->mask[5]);
    n2 ^= f(c, n1 + c->key[6] + c->mask[6]);
    n1 ^= f(c, n2 + c->key[7] + c->mask[7]);

    n2 ^= f(c, n1 + c->key[7] + c->mask[7]);
    n1 ^= f(c, n2 + c->key[6] + c->mask[6]);
    n2 ^= f(c, n1 + c->key[5] + c->mask[5]);
    n1 ^= f(c, n2 + c->key[4] + c->mask[4]);
    n2 ^= f(c, n1 + c->key[3] + c->mask[3]);
    n1 ^= f(c, n2 + c->key[2] + c->mask[2]);
    n2 ^= f(c, n1 + c->key[1] + c->mask[1]);
    n1 ^= f(c, n2 + c->key[0] + c->mask[0]);

    n2 ^= f(c, n1 + c->key[7] + c->mask[7]);
    n1 ^= f(c, n2 + c->key[6] + c->mask[6]);
    n2 ^= f(c, n1 + c->key[5] + c->mask[5]);
    n1 ^= f(c, n2 + c->key[4] + c->mask[4]);
    n2 ^= f(c, n1 + c->key[3] + c->mask[3]);
    n1 ^= f(c, n2 + c->key[2] + c->mask[2]);
    n2 ^= f(c, n1 + c->key[1] + c->mask[1]);
    n1 ^= f(c, n2 + c->key[0] + c->mask[0]);

    n2 ^= f(c, n1 + c->key[7] + c->mask[7]);
    n1 ^= f(c, n2 + c->key[6] + c->mask[6]);
    n2 ^= f(c, n1 + c->key[5] + c->mask[5]);
    n1 ^= f(c, n2 + c->key[4] + c->mask[4]);
    n2 ^= f(c, n1 + c->key[3] + c->mask[3]);
    n1 ^= f(c, n2 + c->key[2] + c->mask[2]);
    n2 ^= f(c, n1 + c->key[1] + c->mask[1]);
    n1 ^= f(c, n2 + c->key[0] + c->mask[0]);

    out[7 - 0] = (byte)(n2 & 0xff);
    out[7 - 1] = (byte)((n2 >> 8) & 0xff);
    out[7 - 2] = (byte)((n2 >> 16) & 0xff);
    out[7 - 3] = (byte)(n2 >> 24);
    out[7 - 4] = (byte)(n1 & 0xff);
    out[7 - 5] = (byte)((n1 >> 8) & 0xff);
    out[7 - 6] = (byte)((n1 >> 16) & 0xff);
    out[7 - 7] = (byte)(n1 >> 24);
}


/* (low-level) Encrypts several blocks in ECB mode */
void magma_enc(magma_ctx* c, const byte* clear, byte* cipher, int blocks)
{
    int i;
    for (i = 0; i < blocks; i++) {
        magmacrypt(c, clear, cipher);
        clear += 8;
        cipher += 8;
    }
}

/* (low-level) Decrypts several blocks in ECB mode */
void magma_dec(magma_ctx* c, const byte* cipher, byte* clear, int blocks)
{
    int i;
    for (i = 0; i < blocks; i++) {
        magmadecrypt(c, cipher, clear);
        clear += 8;
        cipher += 8;
    }
}


/* Encrypts one block using specified key */
void magma_enc_with_key(magma_ctx* c, const byte* key, const byte* inblock,
    byte* outblock)
{
    magma_key_nomask(c, key);
    magmacrypt(c, inblock, outblock);
}

void magma_dec_with_key(magma_ctx* c, const byte* key, const byte* inblock,
    byte* outblock)
{
    magma_key_nomask(c, key);
    magmadecrypt(c, inblock, outblock);
}

static void magma_key_impl(magma_ctx* c, const byte* k)
{
    int i, j;
    for (i = 0, j = 0; i < 8; ++i, j += 4) {
        c->key[i] =
            (k[j + 3] | (k[j + 2] << 8) | (k[j + 1] << 16) | ((word32)k[j] <<
                24)) - c->mask[i];
    }
}


/* Set 256 bit key into context without key mask */
void magma_key_nomask(magma_ctx* c, const byte* k)
{
    memset(c->mask, 0, sizeof(c->mask));
    magma_key_impl(c, k);
}




/* (high-level) Encrypts several blocks in ECB mode */
void magma_enc_ecb(const byte* key, const byte* inblock, byte* outblock, int blocks) {
    magma_ctx c;
    kboxinit(&c, &gost28147_TC26ParamSetZ);
    magma_key_nomask(&c, key);
    magma_enc(&c, inblock, outblock, blocks);
}

/* (high-level) Decrypts several blocks in ECB mode */
void magma_dec_ecb(const byte* key, const byte* inblock, byte* outblock, int blocks) {
    magma_ctx c;
    kboxinit(&c, &gost28147_TC26ParamSetZ);
    magma_key_nomask(&c, key);
    magma_dec(&c, inblock, outblock, blocks);
}



/* (low-level) Encrypt several full blocks in CBC mode */
void magma_enc_cbc_low(magma_ctx* c, const byte* key, const byte* iv, const byte* in, byte* out, int size) {
    const byte* in_ptr = in;
    byte* out_ptr = out;
    byte iv_temp[8];
    memcpy(iv_temp, iv, 8);

    magma_key_nomask(c, key);

    while (size > 0) {
        for (int i = 0; i < 8; i++) {
            out_ptr[i] = iv_temp[i] ^ in_ptr[i];
        }
        magmacrypt(c, out_ptr, out_ptr);
        memcpy(iv_temp, out_ptr, 8);
        out_ptr += 8;
        in_ptr += 8;
        size -= 8;
    }
}

//for ECB decryption based version
void magma_enc_cbc_inv_low(magma_ctx* c, const byte* key, const byte* iv, const byte* in, byte* out, int size) {
    const byte* in_ptr = in;
    byte* out_ptr = out;
    byte iv_temp[8];
    memcpy(iv_temp, iv, 8);

    magma_key_nomask(c, key);

    while (size > 0) {
        for (int i = 0; i < 8; i++) {
            out_ptr[i] = iv_temp[i] ^ in_ptr[i];
        }
        magmadecrypt(c, out_ptr, out_ptr);
        memcpy(iv_temp, out_ptr, 8);
        out_ptr += 8;
        in_ptr += 8;
        size -= 8;
    }
}



/* (low-level) Decrypt several full blocks in CBC mode */
void magma_dec_cbc_low(magma_ctx* c, const byte* key, const byte* iv, const byte* in, byte* out, int size) {
    byte b[8];
    byte d[8];
    const byte* in_ptr = in;
    byte* out_ptr = out;
    byte iv_temp[8];
    memcpy(iv_temp, iv, 8);

    magma_key_nomask(c, key);

    while (size > 0) {
        magmadecrypt(c, in_ptr, b);
        memcpy(d, in_ptr, 8);
        for (int i = 0; i < 8; i++) {
            out_ptr[i] = iv_temp[i] ^ b[i];
        }
        memcpy(iv_temp, d, 8);
        out_ptr += 8;
        in_ptr += 8;
        size -= 8;
    }
}

//for ECB decryption based version
void magma_dec_cbc_inv_low(magma_ctx* c, const byte* key, const byte* iv, const byte* in, byte* out, int size) {
    byte b[8];
    byte d[8];
    const byte* in_ptr = in;
    byte* out_ptr = out;
    byte iv_temp[8];
    memcpy(iv_temp, iv, 8);

    magma_key_nomask(c, key);

    while (size > 0) {
        magmacrypt(c, in_ptr, b);
        memcpy(d, in_ptr, 8);
        for (int i = 0; i < 8; i++) {
            out_ptr[i] = iv_temp[i] ^ b[i];
        }
        memcpy(iv_temp, d, 8);
        out_ptr += 8;
        in_ptr += 8;
        size -= 8;
    }
}



/* (high-level) Encrypt several full blocks in CBC mode */
void magma_enc_cbc(const byte* key, const byte* iv, const byte* in, byte* out, int blocks) {
    magma_ctx c;
    kboxinit(&c, &gost28147_TC26ParamSetZ);
    memcpy(out, iv, 8);
    magma_enc_cbc_low(&c, key, iv, in, out + 8, blocks * 8);
}

void magma_enc_cbc_inv(const byte* key, const byte* iv, const byte* in, byte* out, int blocks) {
    magma_ctx c;
    kboxinit(&c, &gost28147_TC26ParamSetZ);
    memcpy(out, iv, 8);
    magma_enc_cbc_inv_low(&c, key, iv, in, out + 8, blocks * 8);
}


/* (high-level) Decrypt several full blocks in CBC mode */
void magma_dec_cbc(const byte* key, const byte* in, byte* out, int blocks) {
    magma_ctx c;
    kboxinit(&c, &gost28147_TC26ParamSetZ);
    uint8_t iv[8];
    memcpy(iv, in, 8);
    magma_dec_cbc_low(&c, key, iv, in + 8, out, blocks * 8);
}

void magma_dec_cbc_inv(const byte* key, const byte* in, byte* out, int blocks) {
    magma_ctx c;
    kboxinit(&c, &gost28147_TC26ParamSetZ);
    const uint8_t* iv = in;
    magma_dec_cbc_inv_low(&c, key, iv, in + 8, out, blocks * 8);
}



/* MAC calculating */
void get_mac(magma_ctx* ctx, byte* buffer, byte* buf2, int n_key)
{
    byte r[8] = { 0 };
    magmacrypt(ctx, r, r);

    int f = r[0] & 128;
    for (int j = 0; j <= n_key; j++) { //n_key = 0 or 1
        for (int i = 0; i < 7; i++)
        {
            r[i] = r[i] << 1;
            if (r[i + 1] & 128)
                r[i] ^= 1;
        }
        r[7] <<= 1;
        if (f) r[7] &= 0x1b;
    }

    for (int i = 0; i < 8; i++) buffer[i] ^= r[i] ^ buf2[i];
    magmacrypt(ctx, buffer, buffer);
}

void magma_mac_low(magma_ctx* ctx, int mac_len, const uint8_t* data, uint8_t* mac, unsigned int data_len)
{
    byte buffer[8] = { 0 };
    byte buf2[8] = { 0 };
    int i;
    int n_key = 0;
    
    for (i = 0; i + 8 < data_len; i += 8) {
        for (int k = 0; k < 8; k++) {
            buffer[k] ^= data[i + k];
        }
        magmacrypt(ctx, buffer, buffer);
    }
    if (i + 8 > data_len) n_key++;
    memcpy(buf2, data + i, data_len - i);
    get_mac(ctx, buffer, buf2, n_key);
    memcpy(mac, buffer, 8);
}


/* High-level MAC computation */
void magma_mac(const byte* key, const byte* indata, byte* outdata, const int blocks) {
    magma_ctx c;
    kboxinit(&c, &gost28147_TC26ParamSetZ);
    magma_key_nomask(&c, key);
    magma_mac_low(&c, 64, indata, outdata, blocks * 8);
}
