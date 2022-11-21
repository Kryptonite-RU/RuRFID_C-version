#define _CRT_SECURE_NO_WARNINGS
#include "interacting.h"


int main() {

	//log file
	FILE* log;
	if (!(log = fopen("log.txt", "w"))) {
		printf("Cannot open log file\n");
		return INVALID_LOG_FILE;
	}

	// TAG'S STEP
	//sending ID
	uint8_t tag_id;
	get_tag_id(&tag_id);
	fprintf(log, "Tag to Interrogator:           My ID: %x\n", tag_id);


	// INTERROGATOR'S STEP
	//checking tag's ID
	if (check_id(tag_id)) {
		err(log, INVALID_ID);
		return INVALID_ID;
	}


	//generating KeyID
	uint8_t key_id;
	get_key_id(&key_id);

	//interaction according to the method
	if (AUTHMETHOD == TAM) {
		//making TAM_message
		uint8_t IChallenge[(ChalLen + 4) / 8];
		get_ichallenge(IChallenge);
		uint8_t optional_params[2];
		get_optional_params(optional_params);
		uint8_t TAM_message[(ChalLen + 28) / 8];
		TAM_message_making(TAM_message, key_id, IChallenge, optional_params);
		uint8_t TAM_message_size = (ChalLen + 28) / 8;


		fprintf(log, "Interrogator to Tag:     TAM_message: ");
		for (int i = 0; i < TAM_message_size; i++) {
			fprintf(log, "%02x", TAM_message[i]);
		}
		fprintf(log, "\n");


		
		// TAG's step
		//checking TAM_message
		uint8_t tag_AM; //AuthMethod that tag recognized
		uint8_t TAM_message_error = check_message(TAM_message, TAM_message_size, &tag_AM);
		if (TAM_message_error) {
			err(log, TAM_message_error);
			return TAM_message_error;
		}

		//making TAM_response
		uint8_t TAM_response[18 * n / 8];
		uint8_t TAM_response_size;
		tag_processing(tag_AM, TAM_message, TAM_response, &TAM_response_size);

		fprintf(log, "Tag to Interrogator:    TAM_response: ");
		for (int i = 0; i < TAM_response_size; i++) {
			fprintf(log, "%02x", TAM_response[i]);
		}
		fprintf(log, "\n");



		// INTERROGATOR'S STEP
		//checking TAM_response
		switch (PROTMODE) { //checking size of TAM_response
		case 0x00: 
			if (TAM_response_size == (ChalLen + 4) / 8) break;
			else {
				err(log, INVALID_TAM_RESPONSE_SIZE);
				return INVALID_TAM_RESPONSE_SIZE;
			}
		case 0x02:
			if (TAM_response_size == (ChalLen + 4) / 8 + (optional_params[1] & 0x0F) * n / 8 + n / 8) break;
			else {
				err(log, INVALID_TAM_RESPONSE_SIZE);
				return INVALID_TAM_RESPONSE_SIZE;
			}
		case 0x03:
			if (TAM_response_size == (ChalLen + 4) / 8 + ((optional_params[1] & 0x0F) + 1) * n / 8 + n / 8) break;
			else {
				err(log, INVALID_TAM_RESPONSE_SIZE);
				return INVALID_TAM_RESPONSE_SIZE;
			}
		}


		//decryption TRESP
		uint8_t tag_tresp[(ChalLen + 4) / 8];
		uint8_t key[32];
		get_key(key, key_id);
		decryption(key, TAM_response, tag_tresp, 1);

		uint8_t c_TAM;
		switch (PROTMODE) {
		case 0x00:
			c_TAM = 0;
			break;
		case 0x02:
			c_TAM = 1;
			break;
		case 0x03:
			c_TAM = 2;
			break;
		}

		uint8_t interrogator_tresp[(ChalLen + 4) / 8];
		memcpy(interrogator_tresp, IChallenge, (ChalLen + 4) / 8);
		interrogator_tresp[0] += c_TAM << 4;

		for (int i = 0; i < (ChalLen + 4) / 8; i++) {
			if (tag_tresp[i] != interrogator_tresp[i]) {
				err(log, INVALID_TRESP);
				return INVALID_TRESP;
			}
		}


		//authentication was successful, processing data
		if(PROTMODE) {
			uint8_t data[15 * n / 8];
			uint8_t TAM_data_error = processing_data(TAM_response, TAM_response_size, key_id, data, 0);
			if (TAM_data_error) {
				err(log, TAM_data_error);
				return TAM_data_error;
			}

			fprintf(log, "Interrogator:             I recieved: ");
			for (int i = 0; i < TAM_response_size - 2 * n / 8 - (PROTMODE - 2) * n / 8; i++) {
				fprintf(log, "%02x", data[i]);
			}
			fprintf(log, "\n");
		}
		fprintf(log, "Interrogator:          Authentication was successful.");


	}
		else if (AUTHMETHOD == IAM) {
			//making IAM1_message
			uint8_t IAM1_message[2];
			uint8_t IAM1_message_size = 2;
			IAM1_message_making(IAM1_message, key_id);

			fprintf(log, "Interrogator to Tag:    IAM1_message: ");
			fprintf(log, "%02x%02x\n", IAM1_message[0], IAM1_message[1]);


			// TAG'S STEP
			//checking IAM1_message
			uint8_t tag_AM; //AuthMethod that tag recognized
			uint8_t IAM1_message_error = check_message(IAM1_message, IAM1_message_size, &tag_AM);
			if (IAM1_message_error) {
				err(log, IAM1_message_error);
				return IAM1_message_error;
			}

			//making IAM1_response
			uint8_t IAM1_response[(ChalLen + 4) / 8];
			uint8_t IAM1_response_size;
			uint8_t TChallenge[(ChalLen + 4) / 8];
			get_tchallenge(TChallenge);
			memcpy(IAM1_response, TChallenge, (ChalLen + 4) / 8);
			tag_processing(tag_AM, IAM1_message, IAM1_response, &IAM1_response_size);
			uint8_t tag_key_id = IAM1_message[1];

			fprintf(log, "Tag to Interrogator:   IAM1_response: ");
			for (int i = 0; i < IAM1_response_size; i++) {
				fprintf(log, "%02x", IAM1_response[i]);
			}
			fprintf(log, "\n");


			// INTERROGATOR'S STEP
			//checking IAM1_response
			if (IAM1_response_size != (ChalLen + 4) / 8) {
				err(log, INVALID_IAM1_RESPONSE_SIZE);
				return INVALID_IAM1_RESPONSE_SIZE;
			}
			if (IAM1_response[IAM1_response_size - 1] & 0x0F) {
				err(log, INVALID_PAD_I);
				return INVALID_PAD_I;
			}


			//making IRESP
			uint8_t iresp[(ChalLen + 4) / 8];
			memcpy(iresp, IAM1_response, (ChalLen + 4) / 8);
			for (int i = (ChalLen + 4) / 8 - 1; i > 0; i--) {
				iresp[i] >>= 4;
				iresp[i] += iresp[i - 1] << 4;
			}
			iresp[0] >>= 4;

			//define C_IAM
			uint8_t c_IAM;
			switch (PROTMODE) {
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

			iresp[0] += c_IAM << 4;

			//encryption of (C_IAM||TChallenge) to make IRESP
			uint8_t key[32];
			get_key(key, key_id);
			encryption(key, iresp, iresp, 1);

			//making IAM2_message
			uint8_t optional_params[2];
			get_optional_params(optional_params);
			uint8_t IAM2_message[3 + 18 * n / 8];
			uint8_t IAM2_message_size;
			IAM2_message_making(IAM2_message, &IAM2_message_size, key_id, iresp, optional_params);

			
			fprintf(log, "Interrogator to Tag:    IAM2_message: ");
			for (int i = 0; i < IAM2_message_size; i++) {
				fprintf(log, "%02x", IAM2_message[i]);
			}
			fprintf(log, "\n");


			// TAG'S STEP
			//checking IAM2_message
			uint8_t IAM2_message_error = check_message(IAM2_message, IAM2_message_size, &tag_AM);
			if (IAM2_message_error) {
				err(log, IAM2_message_error);
				return IAM2_message_error;
			}

			//making IAM2_response
			uint8_t IAM2_response[(ChalLen + 4) / 8];
			uint8_t IAM2_response_size;
			memcpy(IAM2_response, TChallenge, (ChalLen + 4) / 8);
			tag_processing(tag_AM, IAM2_message, IAM2_response, &IAM2_response_size);

			if (IAM2_response[0]) {
				err(log, INVALID_IRESP);
				return INVALID_IRESP;
			}


			if (PROTMODE) {
				uint8_t data[15 * n / 8];
				uint8_t IAM_data_error;
				IAM_data_error = processing_data(IAM2_message + 3, IAM2_message_size - 3, tag_key_id, data, 1);
				if (IAM_data_error) {
					err(log, IAM_data_error);
					return IAM_data_error;
				}


				fprintf(log, "Tag:                      I recieved: ");
				for (int i = 0; i < IAM2_message_size - 2 * n / 8 - (PROTMODE - 2) * n / 8 - 3; i++) {
					fprintf(log, "%02x", data[i]);
				}
				fprintf(log, "\n");
			}

			fprintf(log, "Tag to Interrogator:   IAM2_response: %x\n", IAM2_response[0]);


			//autentication was successful
			if(!IAM2_response[0]) fprintf(log, "Interrogator:          Authentication was successful.");
		}
		else {//MAM
			//making MAM1_message
			uint8_t IChallenge[(ChalLen + 4) / 8];
			get_ichallenge(IChallenge);
			uint8_t optional_params[2];
			get_optional_params(optional_params);
			uint8_t MAM1_message[(ChalLen + 36) / 8];
			MAM1_message_making(MAM1_message, key_id, IChallenge, optional_params);
			uint8_t MAM1_message_size = (ChalLen + 36) / 8;


			fprintf(log, "Interrogator to Tag:    MAM1_message: ");
			for (int i = 0; i < MAM1_message_size; i++) {
				fprintf(log, "%02x", MAM1_message[i]);
			}
			fprintf(log, "\n");



			// TAG's step
			//checking MAM1_message
			uint8_t tag_AM; //AuthMethod that tag recognized
			uint8_t MAM1_message_error = check_message(MAM1_message, MAM1_message_size, &tag_AM);
			if (MAM1_message_error) {
				err(log, MAM1_message_error);
				return MAM1_message_error;
			}

			//making MAM1_response
			uint8_t MAM1_response[19 * n / 8];
			uint8_t MAM1_response_size;
			
			uint8_t TChallenge[(ChalLen + 4) / 8];
			get_tchallenge(TChallenge);
			memcpy(MAM1_response, TChallenge, (ChalLen + 4) / 8);
			tag_processing(tag_AM, MAM1_message, MAM1_response, &MAM1_response_size);
			uint8_t tag_key_id = (MAM1_message[0] << 4) + (MAM1_message[1] >> 4);

			fprintf(log, "Tag to Interrogator:   MAM1_response: ");
			for (int i = 0; i < MAM1_response_size; i++) {
				fprintf(log, "%02x", MAM1_response[i]);
			}
			fprintf(log, "\n");


			// INTERROGATOR'S STEP
			//checking MAM1_response
			switch (PROTMODE) { //checking size of MAM1_response
			case 0x00:
				if (MAM1_response_size == 2 * (ChalLen + 4) / 8) break;
				else {
					err(log, INVALID_MAM1_RESPONSE_SIZE);
					return INVALID_MAM1_RESPONSE_SIZE;
				}
			case 0x02:
				if (MAM1_response_size == 2 * (ChalLen + 4) / 8 + (optional_params[1] & 0x0F) * n / 8 + n / 8) break;
				else {
					err(log, INVALID_MAM1_RESPONSE_SIZE);
					return INVALID_MAM1_RESPONSE_SIZE;
				}
			case 0x03:
				if (MAM1_response_size == 2 * (ChalLen + 4) / 8 + ((optional_params[1] & 0x0F) + 1) * n / 8 + n / 8) break;
				else {
					err(log, INVALID_MAM1_RESPONSE_SIZE);
					return INVALID_MAM1_RESPONSE_SIZE;
				}
			}


			if (MAM1_response[MAM1_response_size - 1] & 0x0F) {
				err(log, INVALID_PAD_I);
				return INVALID_PAD_I;
			}


			//decryption TRESP
			uint8_t tag_tresp[(ChalLen + 4) / 8];
			uint8_t key[32];
			get_key(key, key_id);
			decryption(key, MAM1_response, tag_tresp, 1);

			uint8_t c_MAM1;
			switch (PROTMODE) {
			case 0x00:
				c_MAM1 = 6;
				break;
			case 0x02:
				c_MAM1 = 7;
				break;
			case 0x03:
				c_MAM1 = 8;
				break;
			}

			uint8_t interrogator_tresp[(ChalLen + 4) / 8];
			memcpy(interrogator_tresp, IChallenge, (ChalLen + 4) / 8);
			interrogator_tresp[0] += c_MAM1 << 4;

			for (int i = 0; i < (ChalLen + 4) / 8; i++) {
				if (tag_tresp[i] != interrogator_tresp[i]) {
					err(log, INVALID_TRESP);
					return INVALID_TRESP;
				}
			}

			if (PROTMODE){
				uint8_t data[15 * n / 8];
				uint8_t MAM1_data_error = processing_data(MAM1_response, MAM1_response_size - n / 8, key_id, data, 0);
				if (MAM1_data_error) {
					err(log, MAM1_data_error);
					return MAM1_data_error;
				}
				fprintf(log, "Interrogator:             I recieved: ");
				for (int i = 0; i < MAM1_response_size - 3 * n / 8 - (PROTMODE - 2) * n / 8; i++) {
					fprintf(log, "%02x", data[i]);
				}
				fprintf(log, "\n");
			}
			fprintf(log, "Interrogator:          Authentication of Tag was successful.\n");



			//making IRESP
			uint8_t iresp[(ChalLen + 4) / 8];
			memcpy(iresp, MAM1_response + MAM1_response_size - (ChalLen + 4) / 8, (ChalLen + 4) / 8);
			for (int i = (ChalLen + 4) / 8 - 1; i > 0; i--) {
				iresp[i] >>= 4;
				iresp[i] += iresp[i - 1] << 4;
			}
			iresp[0] >>= 4;

			//define C_MAM2
			uint8_t c_MAM2;
			switch (PROTMODE) {
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

			iresp[0] += c_MAM2 << 4;

			//encryption of (C_MAM2||TChallenge) to make IRESP
			encryption(key, iresp, iresp, 1);

			//making MAM2_message
			get_optional_params(optional_params);
			uint8_t MAM2_message[4 + 18 * n / 8];
			uint8_t MAM2_message_size;
			MAM2_message_making(MAM2_message, &MAM2_message_size, key_id, iresp, optional_params);


			fprintf(log, "Interrogator to Tag:    MAM2_message: ");
			for (int i = 0; i < MAM2_message_size; i++) {
				fprintf(log, "%02x", MAM2_message[i]);
			}
			fprintf(log, "\n");



			// TAG'S STEP
			//checking MAM2_message
			uint8_t MAM2_message_error = check_message(MAM2_message, MAM2_message_size, &tag_AM);
			if (MAM2_message_error) {
				err(log, MAM2_message_error);
				return MAM2_message_error;
			}
			 
			 
			 
			//making MAM2_response
			uint8_t MAM2_response[(ChalLen + 4) / 8];
			uint8_t MAM2_response_size;
			memcpy(MAM2_response, TChallenge, (ChalLen + 4) / 8);
			tag_processing(tag_AM, MAM2_message, MAM2_response, &MAM2_response_size);

			if (MAM2_response[0]) {
				err(log, INVALID_IRESP);
				return INVALID_IRESP;
			}


			if (PROTMODE) {
				uint8_t data[15 * n / 8] = { 0 };
				uint8_t MAM_data_error;
				MAM_data_error = processing_data(MAM2_message + 3, MAM2_message_size - 3, tag_key_id, data, 1);
				if (MAM_data_error) {
					err(log, MAM_data_error);
					return MAM_data_error;
				}

				fprintf(log, "Tag:                      I recieved: ");
				for (int i = 0; i < MAM2_message_size - 2 * n / 8 - (PROTMODE - 2) * n / 8 - 3; i++) {
					fprintf(log, "%02x", data[i]);
				}
				fprintf(log, "\n");
			}

			fprintf(log, "Tag to Interrogator:   MAM2_response: %x\n", MAM2_response[0]);


			//autentication was successful
			if (!MAM2_response[0]) fprintf(log, "Interrogator:          Authentication of Interrogator was successful.\n");

		}

	
	fclose(log);
	return 0;
}
