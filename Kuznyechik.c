#include "Kuznyechik.h"

//S-box
const unsigned char S_box[256] = { 0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
									0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
									0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
									0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
									0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
									0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
									0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
									0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
									0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
									0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
									0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
									0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
									0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
									0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
									0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
									0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
									0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
									0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
									0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
									0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
									0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
									0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
									0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
									0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
									0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
									0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
									0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
									0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
									0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
									0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
									0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
									0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6 };

//inverse S-box
const unsigned char S_box_1[256] = { 0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
									0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
									0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
									0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
									0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
									0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
									0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
									0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
									0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
									0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
									0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
									0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
									0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
									0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
									0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
									0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
									0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
									0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
									0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
									0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
									0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
									0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
									0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
									0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
									0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
									0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
									0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
									0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
									0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
									0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
									0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
									0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74 };



//implementation of key XOR operation
void Add_key(byte* block, const byte* key) {
	((U64*)block)[0] ^= ((U64*)key)[0];
	((U64*)block)[1] ^= ((U64*)key)[1];
}

//S-box operation
void Sub_bytes(byte* block) {
	for (int i = 0; i < 16; i++) block[i] = S_box[block[i]];
}

//inverse S-box operation
void Sub_bytes_1(byte* block) {
	for (int i = 0; i < 16; i++) block[i] = S_box_1[block[i]];
}


//multiplication table
const byte mul_148[256] = { 0, 148, 235, 127, 21, 129, 254, 106, 42, 190, 193, 85, 63, 171, 212, 64, 84, 192, 191, 43, 65, 213, 170, 62, 126, 234, 149, 1, 107, 255, 128, 20, 168, 60, 67, 215, 189, 41, 86, 194, 130, 22, 105, 253, 151, 3, 124, 232, 252, 104, 23, 131, 233, 125, 2, 150, 214, 66, 61, 169, 195, 87, 40, 188, 147, 7, 120, 236, 134, 18, 109, 249, 185, 45, 82, 198, 172, 56, 71, 211, 199, 83, 44, 184, 210, 70, 57, 173, 237, 121, 6, 146, 248, 108, 19, 135, 59, 175, 208, 68, 46, 186, 197, 81, 17, 133, 250, 110, 4, 144, 239, 123, 111, 251, 132, 16, 122, 238, 145, 5, 69, 209, 174, 58, 80, 196, 187, 47, 229, 113, 14, 154, 240, 100, 27, 143, 207, 91, 36, 176, 218, 78, 49, 165, 177, 37, 90, 206, 164, 48, 79, 219, 155, 15, 112, 228, 142, 26, 101, 241, 77, 217, 166, 50, 88, 204, 179, 39, 103, 243, 140, 24, 114, 230, 153, 13, 25, 141, 242, 102, 12, 152, 231, 115, 51, 167, 216, 76, 38, 178, 205, 89, 118, 226, 157, 9, 99, 247, 136, 28, 92, 200, 183, 35, 73, 221, 162, 54, 34, 182, 201, 93, 55, 163, 220, 72, 8, 156, 227, 119, 29, 137, 246, 98, 222, 74, 53, 161, 203, 95, 32, 180, 244, 96, 31, 139, 225, 117, 10, 158, 138, 30, 97, 245, 159, 11, 116, 224, 160, 52, 75, 223, 181, 33, 94, 202 };
const byte mul_32[256] = { 0, 32, 64, 96, 128, 160, 192, 224, 195, 227, 131, 163, 67, 99, 3, 35, 69, 101, 5, 37, 197, 229, 133, 165, 134, 166, 198, 230, 6, 38, 70, 102, 138, 170, 202, 234, 10, 42, 74, 106, 73, 105, 9, 41, 201, 233, 137, 169, 207, 239, 143, 175, 79, 111, 15, 47, 12, 44, 76, 108, 140, 172, 204, 236, 215, 247, 151, 183, 87, 119, 23, 55, 20, 52, 84, 116, 148, 180, 212, 244, 146, 178, 210, 242, 18, 50, 82, 114, 81, 113, 17, 49, 209, 241, 145, 177, 93, 125, 29, 61, 221, 253, 157, 189, 158, 190, 222, 254, 30, 62, 94, 126, 24, 56, 88, 120, 152, 184, 216, 248, 219, 251, 155, 187, 91, 123, 27, 59, 109, 77, 45, 13, 237, 205, 173, 141, 174, 142, 238, 206, 46, 14, 110, 78, 40, 8, 104, 72, 168, 136, 232, 200, 235, 203, 171, 139, 107, 75, 43, 11, 231, 199, 167, 135, 103, 71, 39, 7, 36, 4, 100, 68, 164, 132, 228, 196, 162, 130, 226, 194, 34, 2, 98, 66, 97, 65, 33, 1, 225, 193, 161, 129, 186, 154, 250, 218, 58, 26, 122, 90, 121, 89, 57, 25, 249, 217, 185, 153, 255, 223, 191, 159, 127, 95, 63, 31, 60, 28, 124, 92, 188, 156, 252, 220, 48, 16, 112, 80, 176, 144, 240, 208, 243, 211, 179, 147, 115, 83, 51, 19, 117, 85, 53, 21, 245, 213, 181, 149, 182, 150, 246, 214, 54, 22, 118, 86 };
const byte mul_133[256] = { 0, 133, 201, 76, 81, 212, 152, 29, 162, 39, 107, 238, 243, 118, 58, 191, 135, 2, 78, 203, 214, 83, 31, 154, 37, 160, 236, 105, 116, 241, 189, 56, 205, 72, 4, 129, 156, 25, 85, 208, 111, 234, 166, 35, 62, 187, 247, 114, 74, 207, 131, 6, 27, 158, 210, 87, 232, 109, 33, 164, 185, 60, 112, 245, 89, 220, 144, 21, 8, 141, 193, 68, 251, 126, 50, 183, 170, 47, 99, 230, 222, 91, 23, 146, 143, 10, 70, 195, 124, 249, 181, 48, 45, 168, 228, 97, 148, 17, 93, 216, 197, 64, 12, 137, 54, 179, 255, 122, 103, 226, 174, 43, 19, 150, 218, 95, 66, 199, 139, 14, 177, 52, 120, 253, 224, 101, 41, 172, 178, 55, 123, 254, 227, 102, 42, 175, 16, 149, 217, 92, 65, 196, 136, 13, 53, 176, 252, 121, 100, 225, 173, 40, 151, 18, 94, 219, 198, 67, 15, 138, 127, 250, 182, 51, 46, 171, 231, 98, 221, 88, 20, 145, 140, 9, 69, 192, 248, 125, 49, 180, 169, 44, 96, 229, 90, 223, 147, 22, 11, 142, 194, 71, 235, 110, 34, 167, 186, 63, 115, 246, 73, 204, 128, 5, 24, 157, 209, 84, 108, 233, 165, 32, 61, 184, 244, 113, 206, 75, 7, 130, 159, 26, 86, 211, 38, 163, 239, 106, 119, 242, 190, 59, 132, 1, 77, 200, 213, 80, 28, 153, 161, 36, 104, 237, 240, 117, 57, 188, 3, 134, 202, 79, 82, 215, 155, 30 };
const byte mul_16[256] = { 0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 195, 211, 227, 243, 131, 147, 163, 179, 67, 83, 99, 115, 3, 19, 35, 51, 69, 85, 101, 117, 5, 21, 37, 53, 197, 213, 229, 245, 133, 149, 165, 181, 134, 150, 166, 182, 198, 214, 230, 246, 6, 22, 38, 54, 70, 86, 102, 118, 138, 154, 170, 186, 202, 218, 234, 250, 10, 26, 42, 58, 74, 90, 106, 122, 73, 89, 105, 121, 9, 25, 41, 57, 201, 217, 233, 249, 137, 153, 169, 185, 207, 223, 239, 255, 143, 159, 175, 191, 79, 95, 111, 127, 15, 31, 47, 63, 12, 28, 44, 60, 76, 92, 108, 124, 140, 156, 172, 188, 204, 220, 236, 252, 215, 199, 247, 231, 151, 135, 183, 167, 87, 71, 119, 103, 23, 7, 55, 39, 20, 4, 52, 36, 84, 68, 116, 100, 148, 132, 180, 164, 212, 196, 244, 228, 146, 130, 178, 162, 210, 194, 242, 226, 18, 2, 50, 34, 82, 66, 114, 98, 81, 65, 113, 97, 17, 1, 49, 33, 209, 193, 241, 225, 145, 129, 177, 161, 93, 77, 125, 109, 29, 13, 61, 45, 221, 205, 253, 237, 157, 141, 189, 173, 158, 142, 190, 174, 222, 206, 254, 238, 30, 14, 62, 46, 94, 78, 126, 110, 24, 8, 56, 40, 88, 72, 120, 104, 152, 136, 184, 168, 216, 200, 248, 232, 219, 203, 251, 235, 155, 139, 187, 171, 91, 75, 123, 107, 27, 11, 59, 43 };
const byte mul_194[256] = { 0, 194, 71, 133, 142, 76, 201, 11, 223, 29, 152, 90, 81, 147, 22, 212, 125, 191, 58, 248, 243, 49, 180, 118, 162, 96, 229, 39, 44, 238, 107, 169, 250, 56, 189, 127, 116, 182, 51, 241, 37, 231, 98, 160, 171, 105, 236, 46, 135, 69, 192, 2, 9, 203, 78, 140, 88, 154, 31, 221, 214, 20, 145, 83, 55, 245, 112, 178, 185, 123, 254, 60, 232, 42, 175, 109, 102, 164, 33, 227, 74, 136, 13, 207, 196, 6, 131, 65, 149, 87, 210, 16, 27, 217, 92, 158, 205, 15, 138, 72, 67, 129, 4, 198, 18, 208, 85, 151, 156, 94, 219, 25, 176, 114, 247, 53, 62, 252, 121, 187, 111, 173, 40, 234, 225, 35, 166, 100, 110, 172, 41, 235, 224, 34, 167, 101, 177, 115, 246, 52, 63, 253, 120, 186, 19, 209, 84, 150, 157, 95, 218, 24, 204, 14, 139, 73, 66, 128, 5, 199, 148, 86, 211, 17, 26, 216, 93, 159, 75, 137, 12, 206, 197, 7, 130, 64, 233, 43, 174, 108, 103, 165, 32, 226, 54, 244, 113, 179, 184, 122, 255, 61, 89, 155, 30, 220, 215, 21, 144, 82, 134, 68, 193, 3, 8, 202, 79, 141, 36, 230, 99, 161, 170, 104, 237, 47, 251, 57, 188, 126, 117, 183, 50, 240, 163, 97, 228, 38, 45, 239, 106, 168, 124, 190, 59, 249, 242, 48, 181, 119, 222, 28, 153, 91, 80, 146, 23, 213, 1, 195, 70, 132, 143, 77, 200, 10 };
const byte mul_192[256] = { 0, 192, 67, 131, 134, 70, 197, 5, 207, 15, 140, 76, 73, 137, 10, 202, 93, 157, 30, 222, 219, 27, 152, 88, 146, 82, 209, 17, 20, 212, 87, 151, 186, 122, 249, 57, 60, 252, 127, 191, 117, 181, 54, 246, 243, 51, 176, 112, 231, 39, 164, 100, 97, 161, 34, 226, 40, 232, 107, 171, 174, 110, 237, 45, 183, 119, 244, 52, 49, 241, 114, 178, 120, 184, 59, 251, 254, 62, 189, 125, 234, 42, 169, 105, 108, 172, 47, 239, 37, 229, 102, 166, 163, 99, 224, 32, 13, 205, 78, 142, 139, 75, 200, 8, 194, 2, 129, 65, 68, 132, 7, 199, 80, 144, 19, 211, 214, 22, 149, 85, 159, 95, 220, 28, 25, 217, 90, 154, 173, 109, 238, 46, 43, 235, 104, 168, 98, 162, 33, 225, 228, 36, 167, 103, 240, 48, 179, 115, 118, 182, 53, 245, 63, 255, 124, 188, 185, 121, 250, 58, 23, 215, 84, 148, 145, 81, 210, 18, 216, 24, 155, 91, 94, 158, 29, 221, 74, 138, 9, 201, 204, 12, 143, 79, 133, 69, 198, 6, 3, 195, 64, 128, 26, 218, 89, 153, 156, 92, 223, 31, 213, 21, 150, 86, 83, 147, 16, 208, 71, 135, 4, 196, 193, 1, 130, 66, 136, 72, 203, 11, 14, 206, 77, 141, 160, 96, 227, 35, 38, 230, 101, 165, 111, 175, 44, 236, 233, 41, 170, 106, 253, 61, 190, 126, 123, 187, 56, 248, 50, 242, 113, 177, 180, 116, 247, 55 };
const byte mul_251[256] = { 0, 251, 53, 206, 106, 145, 95, 164, 212, 47, 225, 26, 190, 69, 139, 112, 107, 144, 94, 165, 1, 250, 52, 207, 191, 68, 138, 113, 213, 46, 224, 27, 214, 45, 227, 24, 188, 71, 137, 114, 2, 249, 55, 204, 104, 147, 93, 166, 189, 70, 136, 115, 215, 44, 226, 25, 105, 146, 92, 167, 3, 248, 54, 205, 111, 148, 90, 161, 5, 254, 48, 203, 187, 64, 142, 117, 209, 42, 228, 31, 4, 255, 49, 202, 110, 149, 91, 160, 208, 43, 229, 30, 186, 65, 143, 116, 185, 66, 140, 119, 211, 40, 230, 29, 109, 150, 88, 163, 7, 252, 50, 201, 210, 41, 231, 28, 184, 67, 141, 118, 6, 253, 51, 200, 108, 151, 89, 162, 222, 37, 235, 16, 180, 79, 129, 122, 10, 241, 63, 196, 96, 155, 85, 174, 181, 78, 128, 123, 223, 36, 234, 17, 97, 154, 84, 175, 11, 240, 62, 197, 8, 243, 61, 198, 98, 153, 87, 172, 220, 39, 233, 18, 182, 77, 131, 120, 99, 152, 86, 173, 9, 242, 60, 199, 183, 76, 130, 121, 221, 38, 232, 19, 177, 74, 132, 127, 219, 32, 238, 21, 101, 158, 80, 171, 15, 244, 58, 193, 218, 33, 239, 20, 176, 75, 133, 126, 14, 245, 59, 192, 100, 159, 81, 170, 103, 156, 82, 169, 13, 246, 56, 195, 179, 72, 134, 125, 217, 34, 236, 23, 12, 247, 57, 194, 102, 157, 83, 168, 216, 35, 237, 22, 178, 73, 135, 124 };

//one cycle of LRS
void Shft_reg(byte* block) {
	byte temp = block[15];
	U64* pntr = (U64*)block;
	pntr[1] <<= 8;
	pntr[1] ^= (pntr[0] >> 56);
	pntr[0] <<= 8;
	block[0] = temp ^ mul_148[block[15] ^ block[1]] ^ mul_32[block[14] ^ block[2]] ^ mul_133[block[13] ^ block[3]] ^ mul_16[block[12] ^ block[4]] ^ mul_194[block[5] ^ block[11]] ^ mul_192[block[6] ^ block[10]] ^ block[7] ^ block[9] ^ mul_251[block[8]];
}

//one cycle of inverse LRS
void Shft_reg_1(byte* block) {
	byte temp = block[0];
	U64* pntr = (U64*)block;
	pntr[0] >>= 8;
	pntr[0] ^= (pntr[1] << 56);
	pntr[1] >>= 8;
	block[15] = temp ^ mul_148[block[14] ^ block[0]] ^ mul_32[block[13] ^ block[1]] ^ mul_133[block[12] ^ block[2]] ^ mul_16[block[11] ^ block[3]] ^ mul_194[block[10] ^ block[4]] ^ mul_192[block[9] ^ block[5]] ^ block[8] ^ block[6] ^ mul_251[block[7]];
}

//linear transform (16 cycles of LRS)
void L(byte* block) {
	for (int i = 0; i < 16; i++) Shft_reg(block);
}

//inverse linear transform (16 cycles of LRS)
void L_1(byte* block) {
	for (int i = 0; i < 16; i++) Shft_reg_1(block);
}

//one round of encryption
void Enc_round(byte* block, const byte* key) {
	Add_key(block, key);
	Sub_bytes(block);
	L(block);
}

//one round of decryption
void Dec_round(byte* block, const byte* key) {
	L_1(block);
	Sub_bytes_1(block);
	Add_key(block, key);
}

//one step of key deployment
void Key_ext_step(const byte* key, const int num_iter) {
	byte c1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, num_iter - 1 };
	byte c2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, num_iter };

	L(c1);
	L(c2);

	byte key1[16] = { 0 };
	Add_key(key1, key);

	Enc_round(key, c1);
	Add_key(key, key + 16);

	memcpy(key + 16, key, 16);

	Enc_round(key, c2);

	Add_key(key, key1);
}

//one round of key deployment
void Key_ext_round(const byte* key, const int num_round) {
	for (int i = 1; i < 5; i++) {
		Key_ext_step(key, 2 * i + 8 * num_round);
	}
}

//key deployment function
void Key_ext_encrypt(const byte* key, const byte* key_encrypt) {
	memcpy(key_encrypt, key, 32);

	for (int i = 1; i < 5; i++) {
		memcpy(key_encrypt + 32 * i, key_encrypt + 32 * (i - 1), 32);
		Key_ext_round(key_encrypt + 32 * i, i - 1);
	}
}

// ECB encryption of one block of plain text
void Encrypt(byte* block, const byte* key) {
	byte key_encrypt[160] = { 0 };
	Key_ext_encrypt(key, key_encrypt);

	for (int i = 0; i < 9; i++) Enc_round(block, key_encrypt + i * 16);

	Add_key(block, key_encrypt + 144);
}

// ECB decryption of one block of plain text
void Decrypt(byte* block, const byte* key) {
	byte key_encrypt[160] = { 0 };
	Key_ext_encrypt(key, key_encrypt);

	Add_key(block, key_encrypt + 144);

	for (int i = 8; i > -1; i--) Dec_round(block, key_encrypt + i * 16);

}


// CBC encryption of one block of plaintext (IV length is 128 bits)
void CBC(byte* plain_text, const byte* key, const int text_len, const byte* IV) {
	int i;
	byte iv_tmp[16];
	memcpy(iv_tmp, IV, 16);

	int num_blocks = (text_len + 127) / 128;

	byte key_encrypt[160] = { 0 };

	Key_ext_encrypt(key, key_encrypt);

	for (i = 0; i < num_blocks; i++) {
		Add_key(plain_text + 16 * i, iv_tmp);
		Encrypt(plain_text + 16 * i, key_encrypt);
		memcpy(iv_tmp, plain_text + 16 * i, 16);
	}

}

void CBC_inv(byte* plain_text, const byte* key, const int text_len, const byte* IV) {
	int i;
	byte iv_tmp[16];
	memcpy(iv_tmp, IV, 16);

	int num_blocks = (text_len + 127) / 128;

	byte key_encrypt[160] = { 0 };

	Key_ext_encrypt(key, key_encrypt);

	for (i = 0; i < num_blocks; i++) {
		Add_key(plain_text + 16 * i, iv_tmp);
		Decrypt(plain_text + 16 * i, key_encrypt);
		memcpy(iv_tmp, plain_text + 16 * i, 16);
	}

}

// CBC decryption of one block of plaintext (IV length is 128 bits)
void CBC_1(byte* cipher_text, const byte* key, const int text_len, const byte* IV) {
	int i;

	byte IV_1[16];

	int num_blocks = (text_len + 127) / 128;

	byte key_encrypt[160] = { 0 };

	Key_ext_encrypt(key, key_encrypt);

	for (i = num_blocks - 1; i > 0; i--) {
		memcpy(IV_1, cipher_text + 16 * (i - 1), 16);
		Decrypt(cipher_text + 16 * i, key_encrypt);
		Add_key(cipher_text + 16 * i, IV_1);
	}

	Decrypt(cipher_text, key_encrypt);
	Add_key(cipher_text, IV);

}


void CBC_1_inv(byte* cipher_text, const byte* key, const int text_len, const byte* IV) {
	int i;

	byte IV_1[16];

	int num_blocks = (text_len + 127) / 128;

	byte key_encrypt[160] = { 0 };

	Key_ext_encrypt(key, key_encrypt);

	for (i = num_blocks - 1; i > 0; i--) {
		memcpy(IV_1, cipher_text + 16 * (i - 1), 16);
		Encrypt(cipher_text + 16 * i, key_encrypt);
		Add_key(cipher_text + 16 * i, IV_1);
	}

	Encrypt(cipher_text, key_encrypt);
	Add_key(cipher_text, IV);

}

// zero-padded plaintext function
void PT_addition(byte* plain_text, const int rem) {
	int i;
	byte a = rem % 8;

	plain_text[rem / 8] &= (((1 << a) - 1) << (8 - a));
	plain_text[rem / 8] |= (1 << (7 - a));

	for (i = rem / 8 + 1; i < 16; i++) plain_text[i] = 0;

}

//sub-keys computation for CMAC
void K_CMAC(byte* K) {
	int i;

	if (K[0] & 128) {
		for (i = 0; i < 15; i++) {
			K[i] = K[i] << 1;

			if (K[i + 1] & 128)	K[i] ^= 1;
		}

		K[15] <<= 1;
		K[15] ^= 135;

	}
	else {
		for (i = 0; i < 15; i++) {
			K[i] = K[i] << 1;

			if (K[i + 1] & 128)	K[i] ^= 1;
		}


		K[15] <<= 1;
	}
}

// CMAC computation
void CMAC(byte* plain_text, const byte* key, const int text_len, const int mac_len) {

	int i, j;

	int num_blocks = (text_len + 127) / 128;

	byte key_encrypt[160] = { 0 };

	Key_ext_encrypt(key, key_encrypt);

	byte R[16] = { 0 };
	Encrypt(R, key_encrypt);

	K_CMAC(R);

	if (text_len % 128) {
		K_CMAC(R);
		PT_addition(plain_text + 16 * (num_blocks - 1), text_len % 128);
	}

	for (i = 0; i < num_blocks - 1; i++) {
		Encrypt(plain_text + 16 * i, key_encrypt);

		for (j = 0; j < 16; j++) plain_text[i * 16 + 16 + j] ^= plain_text[i * 16 + j];

	}

	for (j = 0; j < 16; j++) plain_text[16 * (num_blocks - 1) + j] ^= R[j];

	Encrypt(plain_text + 16 * (num_blocks - 1), key_encrypt);

	memcpy(plain_text, plain_text + text_len / 8 - mac_len, mac_len);
	memset(plain_text + mac_len, 0, text_len / 8 - mac_len);
}



// Final function of ECB encryption
void kuznyechik_enc_ecb(const byte* key, const byte* inblock, byte* outblock, const int blocks) {
	memcpy(outblock, inblock, blocks * 16);
	for (int i = 0; i < blocks; i++) {
		Encrypt(outblock + 16 * i, key);
	}
}

// Final function of ECB decryption
void kuznyechik_dec_ecb(const byte* key, const byte* inblock, byte* outblock, int blocks) {
	memcpy(outblock, inblock, blocks * 16);
	for (int i = 0; i < blocks; i++) {
		Decrypt(outblock + 16 * i, key);
	}
}


// Final function of CBC encryption
void kuznyechik_enc_cbc(const byte* key, const byte* iv, const byte* in, byte* out, int blocks) {
	memcpy(out, iv, 16);
	memcpy(out + 16, in, blocks * 16);
	CBC(out + 16, key, blocks * 128, iv);
}

// Final function of CBC decryption
void kuznyechik_dec_cbc(const byte* key, const byte* in, byte* out, int blocks) {
	byte* iv = in;
	memcpy(out, in + 16, blocks * 16);
	CBC_1(out, key, blocks * 128, iv);
}

// Final function of CBC encryption (based on ECB decryption)
void kuznyechik_enc_cbc_inv(const byte* key, const byte* iv, const byte* in, byte* out, int blocks) {
	memcpy(out, iv, 16);
	memcpy(out + 16, in, blocks * 16);
	CBC_inv(out + 16, key, blocks * 128, iv);
}

// Final function of CBC encryption (based on ECB encryption)
void kuznyechik_dec_cbc_inv(const byte* key, const byte* in, byte* out, int blocks) {
	byte* iv = in;
	memcpy(out, in + 16, blocks * 16);
	CBC_1_inv(out, key, blocks * 128, iv);
}



// Final function of CMAC computation
void kuznyechik_mac(const byte* key, const byte* indata, byte* outdata, const int blocks) {
	memcpy(outdata, indata, blocks * 16);
	CMAC(outdata, key, blocks * 128, 16);
}