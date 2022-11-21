#include "interacting.h"

//processing error with number N
void err(FILE* log, const uint8_t N) {
	switch (N) {
	case INVALID_ID:
		fprintf(log, "Interrogator: Invalid ID\n");
		break;
	case INVALID_AUTHMETHOD:
		fprintf(log, "Tag: Invalid AuthMethod\n");
		break;
	case INVALID_TAM_MESSAGE_SIZE:
		fprintf(log, "Tag: Invalid size of TAM_message\n");
		break;
	case INVALID_TAM_RESPONSE_SIZE:
		fprintf(log, "Interrogator: Invalid size of TAM_response\n");
		break;
	case INVALID_PROTMODE:
		fprintf(log, "Tag: Invalid value of ProtMode\n");
		break;
	case INVALID_KEY_ID:
		fprintf(log, "Tag: Invalid KeyID\n");
		break;
	case INVALID_TRESP:
		fprintf(log, "Interrogator: Invalid TResp\n");
		break;
	case INVALID_MAC:
		fprintf(log, "Data process: Invalid MAC\n");
		break;
	case INVALID_IAM1_MESSAGE_SIZE:
		fprintf(log, "Tag: Invalid size of IAM1_message\n");
		break;
	case INVALID_IAM1_RESPONSE_SIZE:
		fprintf(log, "Interrogator: Invalid size of IAM1_response\n");
		break;
	case INVALID_IAM_STEP:
		fprintf(log, "Tag: Invalid step of IAM\n");
		break;
	case INVALID_PAD_T:
		fprintf(log, "Tag: Invalid PAD of message\n");
		break;
	case INVALID_PAD_I:
		fprintf(log, "Interrogator: Invalid PAD of response\n");
		break;
	case INVALID_IAM2_MESSAGE_SIZE:
		fprintf(log, "Tag: Invalid size of IAM2_message\n");
		break;
	case INVALID_IAM2_RESPONSE_SIZE:
		fprintf(log, "Interrogator: Invalid size of IAM2_response\n");
		break;
	case INVALID_IRESP:
		fprintf(log, "Tag: Invalid IResp\n");
		break;
	case INVALID_MAM_STEP:
		fprintf(log, "Tag: Invalid step of MAM\n");
		break;
	case INVALID_MAM1_MESSAGE_SIZE:
		fprintf(log, "Tag: Invalid size of MAM1_message\n");
		break;
	case INVALID_MAM1_RESPONSE_SIZE:
		fprintf(log, "Interrogator: Invalid size of MAM1_response\n");
		break;
	case INVALID_MAM2_MESSAGE_SIZE:
		fprintf(log, "Tag: Invalid size of MAM2_message\n");
		break;
	case INVALID_MAM2_RESPONSE_SIZE:
		fprintf(log, "Interrogator: Invalid size of MAM2_response\n");
		break;


	case INVALID_AUTH_METHOD:
		fprintf(log, "Tag: Invalid AuthMethod\n");
		break;
	case INACCESSIBLE_MEMORY_AREA:
		fprintf(log, "Tag: Inaccessible memory area\n");
		break;

	default: fprintf(log, "Other error\n");
	}
	fclose(log);
}



/* TAG AND INTERROGATOR INTERACTION */

/* getters */
void get_tag_id(uint8_t* tag_id) {
	*tag_id = (uint8_t)rand();
}

void get_key_id(uint8_t* key_id) {
	*key_id = (uint8_t)rand();
}

//getting (Profile||BlockCount)
void get_optional_params(uint8_t* data) {
	data[0] = 0;
	data[1] = 2;
}

void get_key(uint8_t* key, const uint8_t key_id) {
	/*
	for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
	*/

	uint8_t tmp[32] = { 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 
						0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 
						0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
						0xfe, 0xdb, 0xca, 0x98, 0x76, 0x54, 0x32, 0x10 };
	memcpy(key, tmp, 32);
}

void get_key_e(uint8_t* key, const uint8_t key_id) {
	/*
	for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
	*/

	uint8_t tmp[32] = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
						0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 
						0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	memcpy(key, tmp, 32);
}

void get_key_m(uint8_t* key, const uint8_t key_id) {
	/*
	for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 2);
	*/

	uint8_t tmp[32] = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 
						0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
						0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
						0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	memcpy(key, tmp, 32);
}

void get_tag_data(uint8_t* data, const uint16_t address, const uint8_t blocks) {
	/*
	memset(data, 10, n / 8 * blocks);
	*/
#if CIPHER == MAGMA 
	uint8_t tmp[n / 4] = { 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
							0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88 };
#elif CIPHER == KUZNYECHIK
	uint8_t tmp[n / 4] = { 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
							0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88,
							0x99, 0x99, 0x00, 0x00, 0xAA, 0xAA, 0xBB, 0xBB, 
							0xCC, 0xCC, 0xDD, 0xDD, 0xEE, 0xEE, 0xFF, 0xFF };
#endif
	memcpy(data, tmp, n / 4);

}

void get_int_data(uint8_t* data, const uint16_t address, const uint8_t blocks) {
	/*
	memset(data, 10, n / 8 * blocks);
	*/
#if CIPHER == MAGMA 
	uint8_t tmp[n / 4] = { 0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,
							0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44 };
#elif CIPHER == KUZNYECHIK
	uint8_t tmp[n / 4] = { 0x99, 0x99, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66,
							0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
							0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC,
							0xAA, 0xAA, 0xBB, 0xBB, 0x00, 0x00, 0x55, 0x55 };
#endif
	memcpy(data, tmp, n / 4);

}

void get_ichallenge(uint8_t* vector) {
	/*
	int size = (ChalLen + 4) / 8;
	for (int i = 0; i < size; i++) {
		vector[i] = (uint8_t)rand();
	}
	vector[0] &= 0x0F;
	*/
#if CIPHER == MAGMA 
	uint8_t tmp[n / 8] = { 0x0a, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0xa0 };
#elif CIPHER == KUZNYECHIK
	uint8_t tmp[n / 8] = { 0x0a, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0xa0,
							0x12, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x21 };
#endif
	memcpy(vector, tmp, n / 8);
}

void get_tchallenge(uint8_t* vector) {
	/*
	int size = (ChalLen + 4) / 8;
	for (int i = 0; i < size; i++) {
		vector[i] = (uint8_t)rand();
	}
	vector[size - 1] &= 0xF0;
	*/
#if CIPHER == MAGMA 
	uint8_t tmp[n / 8] = { 0x02, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21 };
#elif CIPHER == KUZNYECHIK
	uint8_t tmp[n / 8] = { 0x02, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21,
							0x19, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x90};
#endif
	for (int i = 0; i < n / 8 - 1; i++) {
		tmp[i] <<= 4;
		tmp[i] += tmp[i + 1] >> 4;
	}
	tmp[n / 8 - 1] <<= 4;
	memcpy(vector, tmp, n / 8);

}


void get_tag_iv(uint8_t* iv) {
	/*
	for (int i = 0; i < n / 8; i++) iv[i] = (uint8_t)rand();
	*/
#if CIPHER == MAGMA 
	uint8_t tmp[n / 8] = { 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21 };
#elif CIPHER == KUZNYECHIK
	uint8_t tmp[n / 8] = { 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21,
							0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21 };
#endif
	memcpy(iv, tmp, n / 8);
}

void get_int_iv(uint8_t* iv) {
	/*
	for (int i = 0; i < n / 8; i++) iv[i] = (uint8_t)rand();
	*/
#if CIPHER == MAGMA 
	uint8_t tmp[n / 8] = { 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76 };
#elif CIPHER == KUZNYECHIK
	uint8_t tmp[n / 8] = { 0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76,
							0x98, 0x76, 0x98, 0x76, 0x98, 0x76, 0x98, 0x76 };
#endif
	memcpy(iv, tmp, n / 8);
}


/* checkers */
uint8_t check_id(const uint8_t id) {
	if (0) return INVALID_ID;
	return 0;
}

uint8_t check_key_id(const uint8_t key_id) {
	if (0) return INVALID_KEY_ID;
	return 0;
}

uint8_t check_opt_params(const uint8_t* opt_params, const uint8_t AuthMethod) {
	if (0) return INACCESSIBLE_MEMORY_AREA;
	return 0;
}

//checking correctness of xAM_message
uint8_t check_message(const uint8_t* message, const uint8_t size, uint8_t* AuthMethod) {
	static uint8_t IAM_step = 0;
	static uint8_t MAM_step = 0;

	*AuthMethod = message[0] >> 6;
	if ((*AuthMethod) == TAM) {
		if (IAM_step || MAM_step) return INVALID_AUTHMETHOD;
		uint8_t ProtMode = (message[0] >> 4) & 0x03;
		if (ProtMode == 1) return INVALID_PROTMODE;
		if (size != (ChalLen + 28) / 8) {
			if (!((size == (ChalLen + 12) / 8) && (ProtMode == 0)))
				return INVALID_TAM_MESSAGE_SIZE;
		}
		else {
			uint8_t* Profile_and_BlockCount = message + size - 2;
			uint8_t opt_params_error = check_opt_params(Profile_and_BlockCount, *AuthMethod);
			if (opt_params_error) return opt_params_error;
		}
		uint8_t key_id = (message[0] << 4) + (message[1] >> 4);
		return check_key_id(key_id);
	}

	else if ((*AuthMethod) == IAM) {
		if (MAM_step) return INVALID_AUTHMETHOD;
		if (!IAM_step) {
			IAM_step++;
			if (size != 2) return INVALID_IAM1_MESSAGE_SIZE;
			if (message[0] & 0x30) return INVALID_IAM_STEP;
			if (message[0] & 0x0F) return INVALID_PAD_T;
			uint8_t key_id = message[1];
			return check_key_id(key_id);
		}
		else {
			if ((message[0] & 0x30) >> 4 != IAM_step) return INVALID_IAM_STEP;
			uint8_t ProtMode = (message[0] & 0x0C) >> 2;

			if (ProtMode == 1) return INVALID_PROTMODE;
			if (message[0] & 0x03) return INVALID_PAD_T;
			if (!ProtMode) {
				if (size != 1 + (ChalLen + 4) / 8) return INVALID_IAM2_MESSAGE_SIZE;
			}
			else {
				uint8_t* Profile_and_BlockCount = message + 1;
				uint8_t opt_params_error = check_opt_params(Profile_and_BlockCount, *AuthMethod);
				if (opt_params_error) return opt_params_error;
				uint8_t BlockCount = Profile_and_BlockCount[1] & 0x0F;
				if (ProtMode == 2) {
					if (size != 3 + (ChalLen + 4) / 8 + BlockCount * n / 8 + n / 8) return INVALID_IAM2_MESSAGE_SIZE;
				}
				else {
					if (size != 3 + (ChalLen + 4) / 8 + (BlockCount + 1) * n / 8 + n / 8) return INVALID_IAM2_MESSAGE_SIZE;
				}
			}
		}
		return 0;
	}
	else if ((*AuthMethod) == MAM) {
		if (IAM_step) return INVALID_AUTHMETHOD;
		if (!MAM_step) {
			MAM_step++;
			if (message[0] & 0x30) return INVALID_MAM_STEP;

			uint8_t ProtMode = (message[0] & 0x03) >> 2;
			if (ProtMode == 1) return INVALID_PROTMODE;
			if (size != (ChalLen + 36) / 8) {
				if (!((size == (ChalLen + 20) / 8) && (ProtMode == 0)))
					return INVALID_MAM1_MESSAGE_SIZE;
			}
			else {
				if ((message[0] << 6) && (message[1] >> 4)) return INVALID_PAD_T;

				uint8_t* Profile_and_BlockCount = message + size - 2;
				uint8_t opt_params_error = check_opt_params(Profile_and_BlockCount, *AuthMethod);
				if (opt_params_error) return opt_params_error;
			}
			uint8_t key_id = (message[0] << 4) + (message[1] >> 4);
			return check_key_id(key_id);
		}
		else{
			if ((message[0] & 0x30) >> 4 != MAM_step) return INVALID_MAM_STEP;
			uint8_t ProtMode = (message[0] & 0x0C) >> 2;

			if (ProtMode == 1) return INVALID_PROTMODE;
			if (message[0] & 0x03) return INVALID_PAD_T;
			if (!ProtMode) {
				if (size != 1 + (ChalLen + 4) / 8) return INVALID_MAM2_MESSAGE_SIZE;
			}
			else {
				uint8_t* Profile_and_BlockCount = message + 1;
				uint8_t opt_params_error = check_opt_params(Profile_and_BlockCount, *AuthMethod);
				if (opt_params_error) return opt_params_error;
				uint8_t BlockCount = Profile_and_BlockCount[1] & 0x0F;
				if (ProtMode == 2) {
					if (size != 3 + (ChalLen + 4) / 8 + BlockCount * n / 8 + n / 8) return INVALID_MAM2_MESSAGE_SIZE;
				}
				else {
					if (size != 3 + (ChalLen + 4) / 8 + (BlockCount + 1) * n / 8 + n / 8) return INVALID_MAM2_MESSAGE_SIZE;
				}
			}
			return 0;
		}
	}

	else return INVALID_AUTH_METHOD;
}


uint8_t processing_data(const uint8_t* message, const uint8_t size, const uint8_t key_id, uint8_t* data, uint8_t is_inverse) {
	//checking MAC
	uint8_t mac_check[17 * n / 8];
	uint8_t key_m[32];
	get_key_m(key_m, key_id);
	mac_computation(key_m, message, mac_check, size / (n / 8) - 1);

	for (int i = 0; i < n / 8; i++) {
		if (mac_check[i] != message[size - n / 8 + i]) return INVALID_MAC;
	}

	//decryption CBC
	if (PROTMODE == 3) {
		uint8_t key_e[32];
		get_key_e(key_e, key_id);
		if(!is_inverse) cbc_decryption(key_e, message + (ChalLen + 4) / 8, data, size / (n / 8) - 3);
		else cbc_inv_decryption(key_e, message + (ChalLen + 4) / 8, data, size / (n / 8) - 3);
	}
	else {
		for (int i = 0; i < size - (ChalLen + 4) / 8 - n / 8; i++) {
			data[i] = message[(ChalLen + 4) / 8 + i];
		}
	}
	return 0;
}




/* making messanges */

//making TAM_message
void TAM_message_making(uint8_t* message, const uint8_t key_id, const uint8_t* IChallenge, const uint8_t* optional_params) {
	int IC_size = (ChalLen + 4) / 8;
	int mes_size = (ChalLen + 28) / 8;
	message[0] = (((AUTHMETHOD << 2) + PROTMODE) << 4) + (key_id >> 4);
	message[1] = (key_id << 4) + IChallenge[0];
	for (int i = 1; i < IC_size; i++) {
		message[i + 1] = IChallenge[i];
	}
	message[mes_size - 2] = optional_params[0];
	message[mes_size - 1] = optional_params[1];
}


//making IAM1_message
void IAM1_message_making(uint8_t* message, const uint8_t key_id) {
	message[0] = AUTHMETHOD << 6;
	message[1] = key_id;
}


//making IAM2_message
void IAM2_message_making(uint8_t* message, uint8_t* message_size, const uint8_t key_id, const uint8_t* iresp, const uint8_t* optional_params) {
	message[0] = ((((AUTHMETHOD << 2) + 1) << 2) + PROTMODE) << 2;
	if (!PROTMODE) {
		memcpy(message + 1, iresp, (ChalLen + 4) / 8);
		*message_size = 1 + (ChalLen + 4) / 8;
	}
	else {
		message[1] = optional_params[0];
		message[2] = optional_params[1];
		uint16_t data_address = ((uint16_t)optional_params[0] << 4) + (optional_params[1] >> 4);
		uint8_t data_size = optional_params[1] & 0x0F;
		uint8_t data[15 * n / 8];
		get_int_data(data, data_address, data_size);

		*message_size = 3 + (ChalLen + 4) / 8 + data_size * n / 8 + n / 8;

		uint8_t tmp[(ChalLen + 4) / 8 + 16 * n / 8];
		memcpy(tmp, iresp, (ChalLen + 4) / 8);
		if (PROTMODE == 2) {
			memcpy(tmp + (ChalLen + 4) / 8, data, data_size * n / 8);
		}
		else {
			uint8_t iv[n / 8];
			get_int_iv(iv);

			uint8_t key_e[32];
			get_key_e(key_e, key_id);

			uint8_t data_tmp[16 * n / 8];
			memcpy(data_tmp, data, data_size * n / 8);
			cbc_inv_encryption(key_e, iv, data_tmp, data, data_size);

			memcpy(tmp + (ChalLen + 4) / 8, data, data_size * n / 8 + n / 8);
			*message_size += n / 8;
		}
		uint8_t key_m[32];
		get_key_m(key_m, key_id);
		uint8_t mac_tmp[17 * n / 8];
		mac_computation(key_m, tmp, mac_tmp, ((*message_size) - n / 8 - 3) / (n / 8));
		memcpy(message + 3, tmp, (*message_size) - n / 8 - 3);
		memcpy(message + (*message_size) - n / 8, mac_tmp, n / 8);
	}
}


//making MAM1_message
void MAM1_message_making(uint8_t* message, const uint8_t key_id, const uint8_t* IChallenge, const uint8_t* optional_params) {
	int IC_size = (ChalLen + 4) / 8;
	int mes_size = (ChalLen + 36) / 8;
	message[0] = ((AUTHMETHOD << 4) + PROTMODE) << 2;
	message[1] = key_id >> 4;
	message[2] = (key_id << 4) + IChallenge[0];
	for (int i = 1; i < IC_size; i++) {
		message[i + 2] = IChallenge[i];
	}
	message[mes_size - 2] = optional_params[0];
	message[mes_size - 1] = optional_params[1];
}


//making MAM2_message
void MAM2_message_making(uint8_t* message, uint8_t* message_size, const uint8_t key_id, const uint8_t* iresp, const uint8_t* optional_params) {
	IAM2_message_making(message, message_size, key_id, iresp, optional_params);
}








/* processing messages */
void tag_processing(uint8_t tag_am, uint8_t* message, uint8_t* response, uint8_t* response_size) {
	if (tag_am == TAM) {
		uint8_t tag_pm = (message[0] << 2) >> 6; //ProtMode that tag recognized

		//define C_TAM
		uint8_t c_TAM;
		switch (tag_pm) {
		case 0:
			c_TAM = 0;
			break;
		case 2:
			c_TAM = 1;
			break;
		case 3:
			c_TAM = 2;
			break;
		}

		//making TRESP
		uint8_t tresp[(ChalLen + 4) / 8];
		tresp[0] = c_TAM << 4;
		tresp[0] += message[1] & 0x0F;
		for (int i = 1; i < (ChalLen + 4) / 8; i++) {
			tresp[i] = message[i + 1];
		}

		uint8_t key[32];
		uint8_t key_id = (message[0] << 4) + (message[1] >> 4);
		get_key(key, key_id);
		encryption(key, tresp, tresp, 1);


		if (tag_pm == 0) {
			*response_size = (ChalLen + 4) / 8;
			memcpy(response, tresp, *response_size);
		}
		else {
			uint16_t data_address = ((uint16_t)message[(ChalLen + 28) / 8 - 2] << 4) + (message[(ChalLen + 28) / 8 - 1] >> 4);
			uint8_t data_size = message[(ChalLen + 28) / 8 - 1] & 0x0F;
			uint8_t data[16 * n / 8];
			get_tag_data(data, data_address, data_size);

			*response_size = (ChalLen + 4) / 8 + data_size * n / 8 + n / 8;

			uint8_t tmp[(ChalLen + 4) / 8 + 16 * n / 8];
			memcpy(tmp, tresp, (ChalLen + 4) / 8);
			if (tag_pm == 2) {
				memcpy(tmp + (ChalLen + 4) / 8, data, data_size * n / 8);
			}
			else {
				uint8_t iv[n / 8];
				get_tag_iv(iv);

				uint8_t key_e[32];
				get_key_e(key_e, key_id);

				uint8_t data_tmp[16 * n / 8];
				memcpy(data_tmp, data, data_size * n / 8);
				cbc_encryption(key_e, iv, data_tmp, data, data_size);

				memcpy(tmp + (ChalLen + 4) / 8, data, data_size * n / 8 + n / 8);
				(*response_size) += n / 8;
			}
			uint8_t key_m[32];
			get_key_m(key_m, key_id);
			uint8_t mac_tmp[17 * n / 8];
			mac_computation(key_m, tmp, mac_tmp, ((*response_size) - (n / 8)) / (n / 8));
			memcpy(response, tmp, (*response_size) - (n / 8));
			memcpy(response + (*response_size) - (n / 8), mac_tmp, n / 8);
		}



	}
	else if (tag_am == IAM) {
		static uint8_t step = 0;
		static uint8_t key_id;
		if (!step) {
			step++;
			key_id = message[1];
			*response_size = (ChalLen + 4) / 8;
		}
		else {
			*response_size = 1;

			uint8_t tag_pm = (message[0] & 0x0C) >> 2;

			uint8_t* interrogator_iresp = message + 3;
			if (!tag_pm) interrogator_iresp -= 2;

			uint8_t tag_iresp[(ChalLen + 4) / 8];

			uint8_t c_IAM;

			switch (tag_pm) {
			case 0:
				c_IAM = 3;
				break;
			case 2:
				c_IAM = 4;
				break;
			case 3:
				c_IAM = 5;
				break;
			}

			memcpy(tag_iresp, response, (ChalLen + 4) / 8);
			for (int i = (ChalLen + 4) / 8 - 1; i > 0; i--) {
				tag_iresp[i] >>= 4;
				tag_iresp[i] += tag_iresp[i - 1] << 4;
			}
			tag_iresp[0] >>= 4;
			tag_iresp[0] += c_IAM << 4;

			uint8_t key[32];
			get_key(key, key_id);
			encryption(key, tag_iresp, tag_iresp, 1);


			response[0] = 0;



			for (int i = 0; i < (ChalLen + 4) / 8; i++) {
				if (tag_iresp[i] != interrogator_iresp[i]) {
					response[0]++;
					break;
				}
			}

		}

	}
	else { //MAM
		static uint8_t step = 0;
		static uint8_t key_id;
		if (!step) {
			step++;
			key_id = (message[1] << 4) + (message[2] >> 4);


			uint8_t tag_pm = (uint8_t)(message[0] << 4) >> 6; //ProtMode that tag recognized

			//define C_MAM1
			uint8_t c_MAM1;
			switch (tag_pm) {
			case 0:
				c_MAM1 = 6;
				break;
			case 2:
				c_MAM1 = 7;
				break;
			case 3:
				c_MAM1 = 8;
				break;
			}

			//making TRESP
			uint8_t tresp[(ChalLen + 4) / 8];
			tresp[0] = c_MAM1 << 4;
			tresp[0] += message[2] & 0x0F;
			for (int i = 1; i < (ChalLen + 4) / 8; i++) {
				tresp[i] = message[i + 2];
			}

			uint8_t key[32];
			get_key(key, key_id);
			encryption(key, tresp, tresp, 1);

			if (tag_pm == 0) {
				*response_size = 2 * (ChalLen + 4) / 8;
				memcpy(response + (ChalLen + 4) / 8, response, (ChalLen + 4) / 8);
				memcpy(response, tresp, (*response_size) / 2);
			}
			else {
				uint16_t data_address = ((uint16_t)message[(ChalLen + 36) / 8 - 2] << 4) + (message[(ChalLen + 36) / 8 - 1] >> 4);
				uint8_t data_size = message[(ChalLen + 36) / 8 - 1] & 0x0F;
				uint8_t data[15 * n / 8];
				get_tag_data(data, data_address, data_size);

				*response_size = 2 * (ChalLen + 4) / 8 + data_size * n / 8 + n / 8;

				uint8_t tmp[(ChalLen + 4) / 8 + 16 * n / 8];
				memcpy(tmp, tresp, (ChalLen + 4) / 8);
				if (tag_pm == 2) {
					memcpy(tmp + (ChalLen + 4) / 8, data, data_size * n / 8);
				}
				else {
					uint8_t iv[n / 8];
					get_tag_iv(iv);

					uint8_t key_e[32];
					get_key_e(key_e, key_id);

					uint8_t data_tmp[16 * n / 8];
					memcpy(data_tmp, data, data_size* n / 8);
					cbc_encryption(key_e, iv, data_tmp, data, data_size);

					memcpy(tmp + (ChalLen + 4) / 8, data, data_size * n / 8 + n / 8);
					(*response_size) += n / 8;
				}
				uint8_t key_m[32];
				get_key_m(key_m, key_id);
				uint8_t mac_tmp[17 * n / 8];

				mac_computation(key_m, tmp, mac_tmp, ((*response_size) - 2 * (n / 8)) / (n / 8));

				uint8_t TChallenge[(ChalLen + 4) / 8];
				memcpy(TChallenge, response, (ChalLen + 4) / 8);

				memcpy(response, tmp, (*response_size) - (ChalLen + 4) / 8 - (n / 8));
				memcpy(response + (*response_size) - (ChalLen + 4) / 8 - (n / 8), mac_tmp, n / 8);
				memcpy(response + (*response_size) - (ChalLen + 4) / 8, TChallenge, (ChalLen + 4) / 8);

			}

		}

		else{
			*response_size = 1;

			uint8_t tag_pm = (message[0] & 0x0C) >> 2;

			uint8_t* interrogator_iresp = message + 3;
			if (!tag_pm) interrogator_iresp -= 2;

			uint8_t tag_iresp[(ChalLen + 4) / 8];

			uint8_t c_MAM2;

			switch (tag_pm) {
			case 0:
				c_MAM2 = 9;
				break;
			case 2:
				c_MAM2 = 10;
				break;
			case 3:
				c_MAM2 = 11;
				break;
			}

			memcpy(tag_iresp, response, (ChalLen + 4) / 8);
			for (int i = (ChalLen + 4) / 8 - 1; i > 0; i--) {
				tag_iresp[i] >>= 4;
				tag_iresp[i] += tag_iresp[i - 1] << 4;
			}
			tag_iresp[0] >>= 4;
			tag_iresp[0] += c_MAM2 << 4;

			uint8_t key[32];
			get_key(key, key_id);
			encryption(key, tag_iresp, tag_iresp, 1);


			response[0] = 0;




			for (int i = 0; i < (ChalLen + 4) / 8; i++) {
				if (tag_iresp[i] != interrogator_iresp[i]) {
					response[0]++;
					break;
				}
			}

		}

	}
}

