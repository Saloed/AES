#pragma once
#include "defines.h"
#include "Tables.h"
#include <iostream>

class AES
{
public:
	explicit AES(std::ostream* err) : _mode()
	{
		_err = err;
	}
	~AES() {}

	int init(MODE mode, OPERATION op, const byte* key, KEY key_len, const byte* init_vector);

	int encrypt_data(const byte * input, int input_byte_len, byte * out_buffer);
	int decrypt_data(const byte * input, int input_byte_len, byte * out_buffer);

#ifdef STRICT_BLOCK

	int encrypt_block(const byte * input, int input_len, byte * out_buffer);
	int decrypt_block(const byte * input, int input_len, byte * out_buffer);

#endif 

private:

	void key_expancion(byte key_matrix[MAX_KEY_COLUMNS][4]);
	void encryption_key_to_decryption();

	void encrypt(const byte a[16], byte b[16]);
	void decrypt(const byte a[16], byte b[16]);




	OPERATION _op = NONE;
	MODE _mode;

	byte     _init_vector[MAX_IV_SIZE];
	byte     _expanded_key[MAX_ROUNDS + 1][4][4];

	uint32 _key_len = 0;
	uint32 _rounds = 0;

	std::ostream* _err;
};


inline int AES::init(MODE mode, OPERATION op, const byte * key, KEY key_len, const byte * init_vector)
{
	_op = op;
	_mode = mode;
	_key_len = key_len;

	switch (key_len)
	{
	case K16B:_rounds = 10; break;
	case K24B:_rounds = 12; break;
	case K32B:_rounds = 14; break;
	default:
		break;
	}

	if (_key_len == 0 || _rounds == 0) { *_err << "Incorrect key length"; return -7; }
	if (key == NULL) { *_err << "Invalid key";	return -7; }

	byte key_matrix[MAX_KEY_COLUMNS][4];
	for (uint32 i = 0; i < _key_len; i++)
		key_matrix[i >> 2][i & 3] = key[i];

	key_expancion(key_matrix);
	if (_op == DECRYPT)
		encryption_key_to_decryption();

	return 0;
}

inline void AES::key_expancion(byte key_matrix[MAX_KEY_COLUMNS][4])
{
	int key_columns = _rounds - 6;
	int rcon_index = 0;

	byte temp_key[MAX_KEY_COLUMNS][4];
	for (int j = 0; j < key_columns; j++)
		*CAST32(temp_key[j]) = *CAST32(key_matrix[j]);

	uint32 r = 0;
	uint32 t = 0;

	// copy values into round key array
	for (int j = 0; (j < key_columns) && (r <= _rounds); )
	{
		for (; (j < key_columns) && (t < 4); j++, t++)
			*CAST32(_expanded_key[r][t]) = *CAST32(temp_key[j]);

		if (t == 4) { r++; t = 0; }
	}

	int kcm1 = key_columns - 1;
	int kcd2 = key_columns / 2;
	int kcd2m1 = kcd2 - 1;

	while (r <= _rounds)
	{
		temp_key[0][0] ^= S[temp_key[kcm1][1]];
		temp_key[0][1] ^= S[temp_key[kcm1][2]];
		temp_key[0][2] ^= S[temp_key[kcm1][3]];
		temp_key[0][3] ^= S[temp_key[kcm1][0]];
		temp_key[0][0] ^= RCON[rcon_index++];

		if (key_columns != 8)
			for (int j = 1; j < key_columns; j++)
				*CAST32(temp_key[j]) ^= *CAST32(temp_key[j - 1]);
		else
		{
			for (int j = 1; j < kcd2; j++)
				*CAST32(temp_key[j]) ^= *CAST32(temp_key[j - 1]);

			temp_key[kcd2][0] ^= S[temp_key[kcd2m1][0]];
			temp_key[kcd2][1] ^= S[temp_key[kcd2m1][1]];
			temp_key[kcd2][2] ^= S[temp_key[kcd2m1][2]];
			temp_key[kcd2][3] ^= S[temp_key[kcd2m1][3]];
			for (int j = kcd2 + 1; j < key_columns; j++)
				*CAST32(temp_key[j]) ^= *CAST32(temp_key[j - 1]);

		}
		for (int j = 0; (j < key_columns) && (r <= _rounds); )
		{
			for (; (j < key_columns) && (t < 4); j++, t++)
				*CAST32(_expanded_key[r][t]) = *CAST32(temp_key[j]);

			if (t == 4) { r++; t = 0; }
		}
	}
}

inline void AES::encryption_key_to_decryption()
{
	byte* temp;

	for (uint32 r = 1; r < _rounds; r++)
	{
		temp = _expanded_key[r][0];
		*CAST32(temp) = *CAST32(U1[temp[0]]) ^ *CAST32(U2[temp[1]]) ^ *CAST32(U3[temp[2]]) ^ *CAST32(U4[temp[3]]);
		temp = _expanded_key[r][1];
		*CAST32(temp) = *CAST32(U1[temp[0]]) ^ *CAST32(U2[temp[1]]) ^ *CAST32(U3[temp[2]]) ^ *CAST32(U4[temp[3]]);
		temp = _expanded_key[r][2];
		*CAST32(temp) = *CAST32(U1[temp[0]]) ^ *CAST32(U2[temp[1]]) ^ *CAST32(U3[temp[2]]) ^ *CAST32(U4[temp[3]]);
		temp = _expanded_key[r][3];
		*CAST32(temp) = *CAST32(U1[temp[0]]) ^ *CAST32(U2[temp[1]]) ^ *CAST32(U3[temp[2]]) ^ *CAST32(U4[temp[3]]);
	}
}

inline void AES::encrypt(const byte a[16], byte b[16])
{
	byte temp[4][4];

	*CAST32(temp[0]) = *CAST32((a)) ^ *CAST32(_expanded_key[0][0]);
	*CAST32(temp[1]) = *CAST32((a + 4)) ^ *CAST32(_expanded_key[0][1]);
	*CAST32(temp[2]) = *CAST32((a + 8)) ^ *CAST32(_expanded_key[0][2]);
	*CAST32(temp[3]) = *CAST32((a + 12)) ^ *CAST32(_expanded_key[0][3]);
	*CAST32((b)) = *CAST32(T1[temp[0][0]])
		^ *CAST32(T2[temp[1][1]])
		^ *CAST32(T3[temp[2][2]])
		^ *CAST32(T4[temp[3][3]]);
	*CAST32((b + 4)) = *CAST32(T1[temp[1][0]])
		^ *CAST32(T2[temp[2][1]])
		^ *CAST32(T3[temp[3][2]])
		^ *CAST32(T4[temp[0][3]]);
	*CAST32((b + 8)) = *CAST32(T1[temp[2][0]])
		^ *CAST32(T2[temp[3][1]])
		^ *CAST32(T3[temp[0][2]])
		^ *CAST32(T4[temp[1][3]]);
	*CAST32((b + 12)) = *CAST32(T1[temp[3][0]])
		^ *CAST32(T2[temp[0][1]])
		^ *CAST32(T3[temp[1][2]])
		^ *CAST32(T4[temp[2][3]]);
	for (uint32 r = 1; r < _rounds - 1; r++)
	{
		*CAST32(temp[0]) = *CAST32((b)) ^ *CAST32(_expanded_key[r][0]);
		*CAST32(temp[1]) = *CAST32((b + 4)) ^ *CAST32(_expanded_key[r][1]);
		*CAST32(temp[2]) = *CAST32((b + 8)) ^ *CAST32(_expanded_key[r][2]);
		*CAST32(temp[3]) = *CAST32((b + 12)) ^ *CAST32(_expanded_key[r][3]);

		*CAST32((b)) = *CAST32(T1[temp[0][0]])
			^ *CAST32(T2[temp[1][1]])
			^ *CAST32(T3[temp[2][2]])
			^ *CAST32(T4[temp[3][3]]);
		*CAST32((b + 4)) = *CAST32(T1[temp[1][0]])
			^ *CAST32(T2[temp[2][1]])
			^ *CAST32(T3[temp[3][2]])
			^ *CAST32(T4[temp[0][3]]);
		*CAST32((b + 8)) = *CAST32(T1[temp[2][0]])
			^ *CAST32(T2[temp[3][1]])
			^ *CAST32(T3[temp[0][2]])
			^ *CAST32(T4[temp[1][3]]);
		*CAST32((b + 12)) = *CAST32(T1[temp[3][0]])
			^ *CAST32(T2[temp[0][1]])
			^ *CAST32(T3[temp[1][2]])
			^ *CAST32(T4[temp[2][3]]);
	}
	*CAST32(temp[0]) = *CAST32((b)) ^ *CAST32(_expanded_key[_rounds - 1][0]);
	*CAST32(temp[1]) = *CAST32((b + 4)) ^ *CAST32(_expanded_key[_rounds - 1][1]);
	*CAST32(temp[2]) = *CAST32((b + 8)) ^ *CAST32(_expanded_key[_rounds - 1][2]);
	*CAST32(temp[3]) = *CAST32((b + 12)) ^ *CAST32(_expanded_key[_rounds - 1][3]);
	b[0] = T1[temp[0][0]][1];
	b[1] = T1[temp[1][1]][1];
	b[2] = T1[temp[2][2]][1];
	b[3] = T1[temp[3][3]][1];
	b[4] = T1[temp[1][0]][1];
	b[5] = T1[temp[2][1]][1];
	b[6] = T1[temp[3][2]][1];
	b[7] = T1[temp[0][3]][1];
	b[8] = T1[temp[2][0]][1];
	b[9] = T1[temp[3][1]][1];
	b[10] = T1[temp[0][2]][1];
	b[11] = T1[temp[1][3]][1];
	b[12] = T1[temp[3][0]][1];
	b[13] = T1[temp[0][1]][1];
	b[14] = T1[temp[1][2]][1];
	b[15] = T1[temp[2][3]][1];
	*CAST32((b)) ^= *CAST32(_expanded_key[_rounds][0]);
	*CAST32((b + 4)) ^= *CAST32(_expanded_key[_rounds][1]);
	*CAST32((b + 8)) ^= *CAST32(_expanded_key[_rounds][2]);
	*CAST32((b + 12)) ^= *CAST32(_expanded_key[_rounds][3]);
}

inline void AES::decrypt(const byte a[16], byte b[16])
{
	byte temp[4][4];

	*CAST32(temp[0]) = *CAST32((a)) ^ *CAST32(_expanded_key[_rounds][0]);
	*CAST32(temp[1]) = *CAST32((a + 4)) ^ *CAST32(_expanded_key[_rounds][1]);
	*CAST32(temp[2]) = *CAST32((a + 8)) ^ *CAST32(_expanded_key[_rounds][2]);
	*CAST32(temp[3]) = *CAST32((a + 12)) ^ *CAST32(_expanded_key[_rounds][3]);

	*CAST32((b)) = *CAST32(T5[temp[0][0]])
		^ *CAST32(T6[temp[3][1]])
		^ *CAST32(T7[temp[2][2]])
		^ *CAST32(T8[temp[1][3]]);
	*CAST32((b + 4)) = *CAST32(T5[temp[1][0]])
		^ *CAST32(T6[temp[0][1]])
		^ *CAST32(T7[temp[3][2]])
		^ *CAST32(T8[temp[2][3]]);
	*CAST32((b + 8)) = *CAST32(T5[temp[2][0]])
		^ *CAST32(T6[temp[1][1]])
		^ *CAST32(T7[temp[0][2]])
		^ *CAST32(T8[temp[3][3]]);
	*CAST32((b + 12)) = *CAST32(T5[temp[3][0]])
		^ *CAST32(T6[temp[2][1]])
		^ *CAST32(T7[temp[1][2]])
		^ *CAST32(T8[temp[0][3]]);
	for (int r = _rounds - 1; r > 1; r--)
	{
		*CAST32(temp[0]) = *CAST32((b)) ^ *CAST32(_expanded_key[r][0]);
		*CAST32(temp[1]) = *CAST32((b + 4)) ^ *CAST32(_expanded_key[r][1]);
		*CAST32(temp[2]) = *CAST32((b + 8)) ^ *CAST32(_expanded_key[r][2]);
		*CAST32(temp[3]) = *CAST32((b + 12)) ^ *CAST32(_expanded_key[r][3]);
		*CAST32((b)) = *CAST32(T5[temp[0][0]])
			^ *CAST32(T6[temp[3][1]])
			^ *CAST32(T7[temp[2][2]])
			^ *CAST32(T8[temp[1][3]]);
		*CAST32((b + 4)) = *CAST32(T5[temp[1][0]])
			^ *CAST32(T6[temp[0][1]])
			^ *CAST32(T7[temp[3][2]])
			^ *CAST32(T8[temp[2][3]]);
		*CAST32((b + 8)) = *CAST32(T5[temp[2][0]])
			^ *CAST32(T6[temp[1][1]])
			^ *CAST32(T7[temp[0][2]])
			^ *CAST32(T8[temp[3][3]]);
		*CAST32((b + 12)) = *CAST32(T5[temp[3][0]])
			^ *CAST32(T6[temp[2][1]])
			^ *CAST32(T7[temp[1][2]])
			^ *CAST32(T8[temp[0][3]]);
	}

	*CAST32(temp[0]) = *CAST32((b)) ^ *CAST32(_expanded_key[1][0]);
	*CAST32(temp[1]) = *CAST32((b + 4)) ^ *CAST32(_expanded_key[1][1]);
	*CAST32(temp[2]) = *CAST32((b + 8)) ^ *CAST32(_expanded_key[1][2]);
	*CAST32(temp[3]) = *CAST32((b + 12)) ^ *CAST32(_expanded_key[1][3]);
	b[0] = S5[temp[0][0]];
	b[1] = S5[temp[3][1]];
	b[2] = S5[temp[2][2]];
	b[3] = S5[temp[1][3]];
	b[4] = S5[temp[1][0]];
	b[5] = S5[temp[0][1]];
	b[6] = S5[temp[3][2]];
	b[7] = S5[temp[2][3]];
	b[8] = S5[temp[2][0]];
	b[9] = S5[temp[1][1]];
	b[10] = S5[temp[0][2]];
	b[11] = S5[temp[3][3]];
	b[12] = S5[temp[3][0]];
	b[13] = S5[temp[2][1]];
	b[14] = S5[temp[1][2]];
	b[15] = S5[temp[0][3]];
	*CAST32((b)) ^= *CAST32(_expanded_key[0][0]);
	*CAST32((b + 4)) ^= *CAST32(_expanded_key[0][1]);
	*CAST32((b + 8)) ^= *CAST32(_expanded_key[0][2]);
	*CAST32((b + 12)) ^= *CAST32(_expanded_key[0][3]);
}

inline int AES::encrypt_data(const byte *input, int input_byte_len, byte *out_buffer) {
	int i, block_amount, pad_len;
	byte block[16], *iv;

	if ((input == nullptr) || (input_byte_len <= 0)) return 0;


	block_amount = input_byte_len / 16;

	switch (_mode)
	{
	case ECB: {
		for (i = block_amount; i > 0; i--)
		{
			encrypt(input, out_buffer);
			input += 16;
			out_buffer += 16;
		}

#ifdef _DEBUG
		*_err << "blocks " << block_amount << '\n';
#endif // DEBUG

		pad_len = 16 - (input_byte_len - 16 * block_amount);

#ifdef _DEBUG
		*_err << "pad_len " << pad_len << '\n';
#endif // DEBUG

		std::memcpy(block, input, 16 - pad_len);

		std::memset(block + 16 - pad_len, pad_len, pad_len);

		encrypt(block, out_buffer);

	} break;

	case CBC: {
		iv = _init_vector;
		for (i = block_amount; i > 0; i--)
		{
			for (int j = 0; j < 4; j++)
				CAST32(block)[j] = CAST32(input)[j] ^ CAST32(iv)[j];

			encrypt(block, out_buffer);
			iv = out_buffer;
			input += 16;
			out_buffer += 16;
		}

#ifdef _DEBUG
		*_err << "blocks " << block_amount << '\n';
#endif // DEBUG

		pad_len = 16 - (input_byte_len - 16 * block_amount);

#ifdef _DEBUG
		*_err << "pad_len " << pad_len << '\n';
#endif // DEBUG

		for (i = 0; i < 16 - pad_len; i++) {
			block[i] = input[i] ^ iv[i];
		}
		for (i = 16 - pad_len; i < 16; i++) {
			block[i] = static_cast<byte>(pad_len) ^ iv[i];
		}
		encrypt(block, out_buffer);
	} break;

	default:return -1;
	}

	return 16 * (block_amount + 1);
}

inline int AES::decrypt_data(const byte *input, int input_byte_len, byte *out_buffer) {
	int i, block_amount, padLen;
	byte block[16];
	uint32 iv[4];

	if ((input == NULL) || (input_byte_len <= 0)) return 0;

	if ((input_byte_len % 16) != 0) { *_err << "Data corrupted\n"; return -1; }

	block_amount = input_byte_len / 16;

	switch (_mode) {
	case ECB:
		for (i = block_amount - 1; i > 0; i--)
		{
			decrypt(input, out_buffer);
			input += 16;
			out_buffer += 16;
		}

		decrypt(input, block);
		padLen = block[15];

		if ((padLen <= 0) || (padLen > 16)) { *_err << "Data corrupted\n"; return -1; }
		for (i = 16 - padLen; i < 16; i++)
			if (block[i] != padLen) { *_err << "Data corrupted\n"; return -1; }

		memcpy(out_buffer, block, 16 - padLen);
		break;

	case CBC:
		memcpy(iv, _init_vector, 16);
		/* all blocks but last */
		for (i = block_amount - 1; i > 0; i--)
		{
			decrypt(input, block);
			CAST32(block)[0] ^= iv[0];
			CAST32(block)[1] ^= iv[1];
			CAST32(block)[2] ^= iv[2];
			CAST32(block)[3] ^= iv[3];
			memcpy(iv, input, 16);
			memcpy(out_buffer, block, 16);
			input += 16;
			out_buffer += 16;
		}
		/* last block */
		decrypt(input, block);
		CAST32(block)[0] ^= iv[0];
		CAST32(block)[1] ^= iv[1];
		CAST32(block)[2] ^= iv[2];
		CAST32(block)[3] ^= iv[3];
		padLen = block[15];

		if ((padLen <= 0) || (padLen > 16)) { *_err << "Data corrupted\n"; return -1; }
		for (i = 16 - padLen; i < 16; i++)
			if (block[i] != padLen) { *_err << "Data corrupted\n"; return -1; }

		memcpy(out_buffer, block, 16 - padLen);
		break;

	default:
		return -1;
	}

	return (16 * block_amount) - padLen;
}


#ifdef STRICT_BLOCK

inline int AES::encrypt_block(const byte *input, int input_len, byte *out_buffer) {
	int i, block_amount;
	byte block[16];

	if (input == 0 || input_len <= 0) return 0;

	block_amount = input_len / 16;

	switch (_mode)
	{
	case ECB:
		for (i = block_amount; i > 0; i--)
		{
			encrypt(input, out_buffer);
			input += 16;
			out_buffer += 16;
		}
		break;

	case CBC:
		for (int j = 0; j < 4; j++)
			CAST32(block)[j] = CAST32(_init_vector)[j] ^ CAST32(input)[j];

		encrypt(block, out_buffer);
		input += 16;
		for (i = block_amount - 1; i > 0; i--)
		{
			for (int j = 0; j < 4; j++)
				CAST32(block)[j] = CAST32(out_buffer)[j] ^ CAST32(input)[j];

			out_buffer += 16;
			encrypt(block, out_buffer);
			input += 16;
		}
		break;
	default:return -1; break;
	}

	return 16 * block_amount;
}

inline int AES::decrypt_block(const byte *input, int input_len, byte *out_buffer) {
	int i, block_amount;
	byte block[16], iv[4][4];

	if ((input == 0) || (input_len <= 0)) return 0;

	block_amount = input_len / 16;

	switch (_mode)
	{
	case ECB:
		for (i = block_amount; i > 0; i--)
		{
			decrypt(input, out_buffer);
			input += 16;
			out_buffer += 16;
		}
		break;

	case CBC:

		*CAST32(iv[0]) = *CAST32((_init_vector));
		*CAST32(iv[1]) = *CAST32((_init_vector + 4));
		*CAST32(iv[2]) = *CAST32((_init_vector + 8));
		*CAST32(iv[3]) = *CAST32((_init_vector + 12));

		for (i = block_amount; i > 0; i--)
		{
			decrypt(input, block);
			CAST32(block)[0] ^= *CAST32(iv[0]);
			CAST32(block)[1] ^= *CAST32(iv[1]);
			CAST32(block)[2] ^= *CAST32(iv[2]);
			CAST32(block)[3] ^= *CAST32(iv[3]);


			*CAST32(iv[0]) = CAST32(input)[0]; CAST32(out_buffer)[0] = CAST32(block)[0];
			*CAST32(iv[1]) = CAST32(input)[1]; CAST32(out_buffer)[1] = CAST32(block)[1];
			*CAST32(iv[2]) = CAST32(input)[2]; CAST32(out_buffer)[2] = CAST32(block)[2];
			*CAST32(iv[3]) = CAST32(input)[3]; CAST32(out_buffer)[3] = CAST32(block)[3];

			input += 16;
			out_buffer += 16;
		}
		break;

	default:
		return -1;
		break;
	}

	return 16 * block_amount;
}

#endif