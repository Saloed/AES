#pragma once
#pragma warning ( disable : 4996)

#define NULL (0)

typedef unsigned long long uint64;
typedef unsigned int       uint32;
typedef unsigned char	   byte;

#define MAX_KEY_COLUMNS (8)
#define MAX_ROUNDS      (14)
#define MAX_IV_SIZE     (16)

#define CAST32(x) ((uint32*)(x)) 
#define CAST(type,x) (static_cast<type>(x))

#define MEGABYTE (1<<20)

enum OPERATION
{
	ENCRYPT,
	DECRYPT,
	NONE
};

enum MODE
{
	ECB,
	CBC
};

enum KEY
{
	K16B = 16,
	K24B = 24,
	K32B = 32
};

