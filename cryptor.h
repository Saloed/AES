#pragma once
#include "defines.h"
#include "AES.h"
#include "MD5.h"
#include "SHA256.h"
#include "SArray.h"

class Cryptor
{
public:

	//stream - for writing errors
	Cryptor(char* input_filename, char* output_filename,
	        OPERATION op, SizedArray<byte>& key, KEY key_type, MODE mode, SizedArray<byte>& init_vector,
	        std::ostream& stream) :
		_in_fname(input_filename), _out_fname(output_filename),
		_key(key), _init_vector(init_vector), _key_type(key_type), _op(op), _mode(mode)
	{
		_err = &stream;
	}

	~Cryptor();

	//check input files 
	int init();

	int process() const;

private:
	char* _in_fname;
	char* _out_fname;
	SizedArray<byte> _key;
	SizedArray<byte> _init_vector;

	KEY _key_type;
	OPERATION _op;
	MODE _mode;

	FILE* _in_file = NULL;
	FILE* _out_file = NULL;

	std::ostream* _err;

	AES* core = NULL;
};


inline Cryptor::~Cryptor()
{
	/*if (_in_file)	fclose(_in_file);
	if (_out_file)	fclose(_out_file);
	*/
	fcloseall();
	if (core) delete core;
}

inline int Cryptor::init()
{
#ifdef _DEBUG
	std::cerr << "input filename | " << _in_fname << "\nout filename | " << _out_fname << std::endl;
#endif
	if (_in_fname == NULL)
	{
		*_err << "File name not specified" << std::endl;
		return -1;
	}
	_in_file = fopen(_in_fname, "rb+");
	if (_in_file == NULL)
	{
		*_err << "Can't open file " << _in_fname << std::endl;
		return -4;
	}
#ifdef _DEBUG
	std::cerr << "input file succesfuly opened" << std::endl;
#endif
	if (_out_fname == NULL)
	{
		uint64 in_size = strlen(_in_fname);
		if (_op == ENCRYPT)
		{
			_out_fname = new char[in_size + 6];
			strcpy(_out_fname, _in_fname);
			strcat(_out_fname, ".crypt");
		}
		else
		{
			_out_fname = new char[in_size + 7];
			strcpy(_out_fname, _in_fname);
			strcat(_out_fname, ".dcrypt");
		}

		if (!strcmp(_in_fname, _out_fname))
		{
			_out_fname = new char[in_size + 5];
			strcpy(_out_fname, _in_fname);
			strcat(_out_fname, ".copy");
		}
	}

	_out_file = fopen(_out_fname, "wb+");
	if (_out_file == NULL)
	{
		*_err << "Can't open file " << _out_fname << std::endl;
		return -5;
	}

	if (_init_vector.isEmpty())
	{
		//_init_vector.set(new byte[MAX_IV_SIZE], MAX_IV_SIZE);
		_init_vector = SizedArray<byte>(new byte[MAX_IV_SIZE], MAX_IV_SIZE);
		for (uint32 i = 0; i < MAX_IV_SIZE; i++)
			_init_vector[i] = 0;
	}

	if (_mode == CBC)
	{
		MD5 hasher;
		_init_vector = hasher.get_hash(_init_vector);

#ifdef _DEBUG
		*_err << "IV md5 hash  |  ";
		for (uint32 i = 0; i < _init_vector.size; ++i)
			*_err << std::hex << static_cast<int>(_init_vector[i]);
		*_err << '\n';
#endif // _DEBUG

	}

	if (_key_type == K16B)
	{
		MD5 hasher;
		_key = hasher.get_hash(_key);

#ifdef _DEBUG
		*_err << "key md5 hash  |  " << _key.size << "  |  ";
		for (uint32 i = 0; i < _key.size; ++i)
			*_err << std::hex << static_cast<int>(_key[i]);
		*_err << '\n';
#endif // _DEBUG

	}

	if (_key_type == K32B)
	{
		SHA256 hasher;
		_key = hasher.get_hash(_key);

#ifdef _DEBUG
		*_err << "key sha256 hash  |  " << _key.size << "  |  ";
		for (uint32 i = 0; i < _key.size; ++i)
			*_err << std::hex << static_cast<int>(_key[i]);
		*_err << '\n';
#endif // _DEBUG

	}

	core = new AES(_err);

	core->init(_mode, _op, _key._arr, _key_type, _init_vector._arr);

	return 0;
}

inline int Cryptor::process() const
{
	if (core == NULL)
	{
		*_err << "core not initialized\n";
		return 4;
	}

	struct stat info;
	int f = fileno(_in_file);
	fstat(f, &info);
	int size = info.st_size;


#ifdef _DEBUG
	*_err << "file size " << size << '\n';
#endif // DEBUG



	byte* input = new byte[size];
	byte* out = new byte[size + 16];

	uint64 read_bytes = fread(input, sizeof(byte), size, _in_file);

#ifdef _DEBUG
	*_err << "bytes read: | " << read_bytes << '\n';
	*_err << "check: | " << input << '\n';
#endif // DEBUG



	int out_size;
	if (_op == ENCRYPT)
		out_size = core->encrypt_data(input, size, out);
	else
		out_size = core->decrypt_data(input, size, out);

	uint64 write_bytes = fwrite(out, sizeof(byte), out_size, _out_file);

#ifdef _DEBUG
	*_err << "succes write to file | size " << out_size << " | write | " << write_bytes << '\n';
#endif // DEBUG



	return 0;
}

