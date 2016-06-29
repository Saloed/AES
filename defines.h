#pragma once
#pragma warning ( disable : 4996)

#define NULL (0)

#define uint64 unsigned long long
#define uint32 unsigned int
#define byte unsigned char

#define MAX_KEY_COLUMNS (8)
#define MAX_ROUNDS      (14)
#define MAX_IV_SIZE     (16)

#define CAST32(x) ((uint32*)(x)) 
#define CAST(type,x) (static_cast<type>(x))


enum OPERATION {
	ENCRYPT,
	DECRYPT,
	NONE
};

enum MODE {
	ECB,
	CBC
};

enum KEY {
	K16B = 16,
	K24B = 24,
	K32B = 32
};



