#pragma once
#include "defines.h"
#include "SArray.h"
#include <memory>

#define MD5_HASH_SIZE ( 16 )


struct MD5Context
{
	uint32     low_bits;
	uint32     high_bits;
	uint32     a;
	uint32     b;
	uint32     c;
	uint32     d;
	byte       buffer[64];
	uint32     block[MD5_HASH_SIZE];
};

/*F, G, H, I   The basic MD5 functions*/

#define F( x, y, z )            ( (z) ^ ((x) & ((y) ^ (z))) )
#define G( x, y, z )            ( (y) ^ ((z) & ((x) ^ (y))) )
#define H( x, y, z )            ( (x) ^ (y) ^ (z) )
#define I( x, y, z )            ( (y) ^ ((x) | ~(z)) )

/* The MD5 transformation for all four rounds.*/

#define STEP( f, a, b, c, d, x, t, s )                          \
    (a) += f((b), (c), (d)) + (x) + (t);                        \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));  \
    (a) += (b);
/*  SET reads 4 input bytes in little-endian byte order
and stores them in a properly aligned word in host byte order.*/

#define SET(n)      (*CAST32(&ptr[(n) * 4]))

class MD5
{
public:
	MD5();
	~MD5();

	SizedArray<byte> get_hash(SizedArray<byte> data);

private:

	void hash_calc();
	byte* transform_function(byte* data, uint64 data_size);

	MD5Context _context;
	byte _hash[MD5_HASH_SIZE];
};

MD5::MD5()
{
	_context.a = 0x67452301;
	_context.b = 0xefcdab89;
	_context.c = 0x98badcfe;
	_context.d = 0x10325476;

	_context.low_bits = 0;
	_context.high_bits = 0;
}

MD5::~MD5()
{
}

inline SizedArray<byte> MD5::get_hash(SizedArray<byte> adata)
{
	uint32 data_size = adata.size;
	byte* data = adata._arr;

	_context.low_bits = data_size & 0x1fffffff;
	_context.high_bits = data_size >> 29;

	if (data_size >= 64)
	{
		byte* temp = transform_function(data, data_size & ~(uint64)0x3f);
		data_size &= 0x3f;
		std::memcpy(_context.buffer, temp, data_size);
	}
	else {
		std::memcpy(_context.buffer, data, data_size);
	}

	uint32    used;
	uint32    free;

	used = _context.low_bits & 0x3f;
	_context.buffer[used++] = 0x80;
	free = 64 - used;

	if (free < 8)
	{
		std::memset(&_context.buffer[used], 0, free);
		transform_function(_context.buffer, 64);
		used = 0;
		free = 64;
	}

	memset(&_context.buffer[used], 0, free - 8);

	hash_calc();

	return SizedArray<byte>(_hash, MD5_HASH_SIZE);
}



inline void MD5::hash_calc()
{
	_context.low_bits <<= 3;
	_context.buffer[56] = (byte)(_context.low_bits);
	_context.buffer[57] = (byte)(_context.low_bits >> 8);
	_context.buffer[58] = (byte)(_context.low_bits >> 16);
	_context.buffer[59] = (byte)(_context.low_bits >> 24);
	_context.buffer[60] = (byte)(_context.high_bits);
	_context.buffer[61] = (byte)(_context.high_bits >> 8);
	_context.buffer[62] = (byte)(_context.high_bits >> 16);
	_context.buffer[63] = (byte)(_context.high_bits >> 24);

	transform_function(_context.buffer, 64);

	_hash[0] = (byte)(_context.a);
	_hash[1] = (byte)(_context.a >> 8);
	_hash[2] = (byte)(_context.a >> 16);
	_hash[3] = (byte)(_context.a >> 24);
	_hash[4] = (byte)(_context.b);
	_hash[5] = (byte)(_context.b >> 8);
	_hash[6] = (byte)(_context.b >> 16);
	_hash[7] = (byte)(_context.b >> 24);
	_hash[8] = (byte)(_context.c);
	_hash[9] = (byte)(_context.c >> 8);
	_hash[10] = (byte)(_context.c >> 16);
	_hash[11] = (byte)(_context.c >> 24);
	_hash[12] = (byte)(_context.d);
	_hash[13] = (byte)(_context.d >> 8);
	_hash[14] = (byte)(_context.d >> 16);
	_hash[15] = (byte)(_context.d >> 24);
}

inline byte * MD5::transform_function(byte * data, uint64 data_size)
{
	byte*     ptr;
	uint32     a;
	uint32     b;
	uint32     c;
	uint32     d;
	uint32     saved_a;
	uint32     saved_b;
	uint32     saved_c;
	uint32     saved_d;

	ptr = data;

	a = _context.a;
	b = _context.b;
	c = _context.c;
	d = _context.d;

	do
	{
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;

		// Round 1
		STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
			STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
			STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
			STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
			STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
			STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
			STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
			STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
			STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
			STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
			STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
			STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
			STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
			STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
			STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
			STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)

			// Round 2
			STEP(G, a, b, c, d, SET(1), 0xf61e2562, 5)
			STEP(G, d, a, b, c, SET(6), 0xc040b340, 9)
			STEP(G, c, d, a, b, SET(11), 0x265e5a51, 14)
			STEP(G, b, c, d, a, SET(0), 0xe9b6c7aa, 20)
			STEP(G, a, b, c, d, SET(5), 0xd62f105d, 5)
			STEP(G, d, a, b, c, SET(10), 0x02441453, 9)
			STEP(G, c, d, a, b, SET(15), 0xd8a1e681, 14)
			STEP(G, b, c, d, a, SET(4), 0xe7d3fbc8, 20)
			STEP(G, a, b, c, d, SET(9), 0x21e1cde6, 5)
			STEP(G, d, a, b, c, SET(14), 0xc33707d6, 9)
			STEP(G, c, d, a, b, SET(3), 0xf4d50d87, 14)
			STEP(G, b, c, d, a, SET(8), 0x455a14ed, 20)
			STEP(G, a, b, c, d, SET(13), 0xa9e3e905, 5)
			STEP(G, d, a, b, c, SET(2), 0xfcefa3f8, 9)
			STEP(G, c, d, a, b, SET(7), 0x676f02d9, 14)
			STEP(G, b, c, d, a, SET(12), 0x8d2a4c8a, 20)

			// Round 3
			STEP(H, a, b, c, d, SET(5), 0xfffa3942, 4)
			STEP(H, d, a, b, c, SET(8), 0x8771f681, 11)
			STEP(H, c, d, a, b, SET(11), 0x6d9d6122, 16)
			STEP(H, b, c, d, a, SET(14), 0xfde5380c, 23)
			STEP(H, a, b, c, d, SET(1), 0xa4beea44, 4)
			STEP(H, d, a, b, c, SET(4), 0x4bdecfa9, 11)
			STEP(H, c, d, a, b, SET(7), 0xf6bb4b60, 16)
			STEP(H, b, c, d, a, SET(10), 0xbebfbc70, 23)
			STEP(H, a, b, c, d, SET(13), 0x289b7ec6, 4)
			STEP(H, d, a, b, c, SET(0), 0xeaa127fa, 11)
			STEP(H, c, d, a, b, SET(3), 0xd4ef3085, 16)
			STEP(H, b, c, d, a, SET(6), 0x04881d05, 23)
			STEP(H, a, b, c, d, SET(9), 0xd9d4d039, 4)
			STEP(H, d, a, b, c, SET(12), 0xe6db99e5, 11)
			STEP(H, c, d, a, b, SET(15), 0x1fa27cf8, 16)
			STEP(H, b, c, d, a, SET(2), 0xc4ac5665, 23)

			// Round 4
			STEP(I, a, b, c, d, SET(0), 0xf4292244, 6)
			STEP(I, d, a, b, c, SET(7), 0x432aff97, 10)
			STEP(I, c, d, a, b, SET(14), 0xab9423a7, 15)
			STEP(I, b, c, d, a, SET(5), 0xfc93a039, 21)
			STEP(I, a, b, c, d, SET(12), 0x655b59c3, 6)
			STEP(I, d, a, b, c, SET(3), 0x8f0ccc92, 10)
			STEP(I, c, d, a, b, SET(10), 0xffeff47d, 15)
			STEP(I, b, c, d, a, SET(1), 0x85845dd1, 21)
			STEP(I, a, b, c, d, SET(8), 0x6fa87e4f, 6)
			STEP(I, d, a, b, c, SET(15), 0xfe2ce6e0, 10)
			STEP(I, c, d, a, b, SET(6), 0xa3014314, 15)
			STEP(I, b, c, d, a, SET(13), 0x4e0811a1, 21)
			STEP(I, a, b, c, d, SET(4), 0xf7537e82, 6)
			STEP(I, d, a, b, c, SET(11), 0xbd3af235, 10)
			STEP(I, c, d, a, b, SET(2), 0x2ad7d2bb, 15)
			STEP(I, b, c, d, a, SET(9), 0xeb86d391, 21)

			a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;

		ptr += 64;
	} while (data_size -= 64);

	_context.a = a;
	_context.b = b;
	_context.c = c;
	_context.d = d;

	return ptr;
}
