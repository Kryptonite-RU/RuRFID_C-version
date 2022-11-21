#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


/* define cipher */
#define MAGMA 1
#define KUZNYECHIK 2

//#define CIPHER MAGMA
#define CIPHER KUZNYECHIK

#if CIPHER == MAGMA
	#include "magma.h"
	#define n 64
	#define ChalLen 60
	#define encryption(key, in, out, blocks) magma_enc_ecb(key, in, out, blocks)
	#define decryption(key, in, out, blocks) magma_dec_ecb(key, in, out, blocks)
	#define cbc_encryption(key, iv, in, out, blocks) magma_enc_cbc(key, iv, in, out, blocks)
	#define cbc_decryption(key, in, out, blocks) magma_dec_cbc(key, in, out, blocks)
	#define cbc_inv_encryption(key, iv, in, out, blocks) magma_enc_cbc_inv(key, iv, in, out, blocks)
	#define cbc_inv_decryption(key, in, out, blocks) magma_dec_cbc_inv(key, in, out, blocks)
	#define mac_computation(key, in, out, blocks) magma_mac(key, in, out, blocks)
#elif CIPHER == KUZNYECHIK
	#include "Kuznyechik.h"
	#define n 128
	#define ChalLen 124
  #define encryption(key, in, out, blocks) kuznyechik_enc_ecb(key, in, out, blocks)
	#define decryption(key, in, out, blocks) kuznyechik_dec_ecb(key, in, out, blocks)
	#define cbc_encryption(key, iv, in, out, blocks) kuznyechik_enc_cbc(key, iv, in, out, blocks)
	#define cbc_decryption(key, in, out, blocks) kuznyechik_dec_cbc(key, in, out, blocks)
	#define cbc_inv_encryption(key, iv, in, out, blocks) kuznyechik_enc_cbc_inv(key, iv, in, out, blocks)
	#define cbc_inv_decryption(key, in, out, blocks) kuznyechik_dec_cbc_inv(key, in, out, blocks)
	#define mac_computation(key, in, out, blocks) kuznyechik_mac(key, in, out, blocks)
#endif



/* define AuthMethod */
#define TAM 0x00
#define IAM 0x01
#define MAM 0x02

#define AUTHMETHOD TAM
//#define AUTHMETHOD IAM
//#define AUTHMETHOD MAM

/* define ProtMode */
//#define PROTMODE 0x00
//#define PROTMODE 0x02
#define PROTMODE 0x03


/* processing types of errors */
#define INVALID_LOG_FILE 101

#define INVALID_ID 102
#define INVALID_AUTHMETHOD 103
#define INVALID_TAM_MESSAGE_SIZE 104
#define INVALID_TAM_RESPONSE_SIZE 105
#define INVALID_PROTMODE 106
#define INVALID_KEY_ID 107
#define INVALID_TRESP 108
#define INVALID_MAC 109
#define INVALID_IAM1_MESSAGE_SIZE 110
#define INVALID_IAM1_RESPONSE_SIZE 111
#define INVALID_IAM_STEP 112
#define INVALID_PAD_T 113
#define INVALID_PAD_I 114
#define INVALID_IAM2_MESSAGE_SIZE 115
#define INVALID_IAM2_RESPONSE_SIZE 116
#define INVALID_IRESP 117
#define INVALID_MAM_STEP 118
#define INVALID_MAM1_MESSAGE_SIZE 119
#define INVALID_MAM1_RESPONSE_SIZE 120
#define INVALID_MAM2_MESSAGE_SIZE 121
#define INVALID_MAM2_RESPONSE_SIZE 122

#define INVALID_AUTH_METHOD 130
#define INACCESSIBLE_MEMORY_AREA 131

void err(FILE* log, const uint8_t N);


/* TAG AND INTERROGATOR INTERACTION */

/* getters */
void get_tag_id(uint8_t* tag_id);
void get_key_id(uint8_t* key_id);
void get_optional_params(uint8_t* data); //getting (Profile||BlockCount)
void get_key(uint8_t* key, const uint8_t key_id);
void get_key_e(uint8_t* key, const uint8_t key_id);
void get_key_m(uint8_t* key, const uint8_t key_id);
void get_tag_data(uint8_t* data, const uint16_t address, const uint8_t blocks);
void get_int_data(uint8_t* data, const uint16_t address, const uint8_t blocks);
void get_ichallenge(uint8_t* vector);
void get_tchallenge(uint8_t* vector);
void get_tag_iv(uint8_t* iv);
void get_int_iv(uint8_t* iv);

/* checkers */
uint8_t check_id(const uint8_t id);
uint8_t check_key_id(const uint8_t key_id);
uint8_t check_opt_params(const uint8_t* opt_params, const uint8_t AuthMethod); //checking (Profile||BlockCount)
uint8_t check_message(const uint8_t* message, const uint8_t size, uint8_t* AuthMethod); //checking correctness of xAM_message



/* making messanges */

//making TAM_message
void TAM_message_making(uint8_t* message, const uint8_t key_id, const uint8_t* IChallenge, const uint8_t* optional_params);
//making IAM1_message
void IAM1_message_making(uint8_t* message, const uint8_t key_id);
//making IAM2_message
void IAM2_message_making(uint8_t* message, uint8_t* message_size, const uint8_t key_id, const uint8_t* iresp, const uint8_t* optional_params);
//making MAM1_message
void MAM1_message_making(uint8_t* message, const uint8_t key_id, const uint8_t* IChallenge, const uint8_t* optional_params);
//making MAM2_message
void MAM2_message_making(uint8_t* message, uint8_t* message_size, const uint8_t key_id, const uint8_t* iresp, const uint8_t* optional_params);



/* processing messages */
void tag_processing(uint8_t tag_am, uint8_t* message, uint8_t* response, uint8_t* response_size);
uint8_t processing_data(const uint8_t* message, const uint8_t size, const uint8_t key_id, uint8_t* data, uint8_t is_inverse);

