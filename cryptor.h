#pragma once
#include "defines.h"
#include "AES.h"
#include "MD5.h"
#include "SHA256.h"
#include "SArray.h"
#include <fstream>

class Cryptor
{
public:

	//stream - for writing errors
	Cryptor(char* input_filename, char* output_filename,
	        OPERATION op, SizedArray<byte>& key, KEY key_type, MODE mode, SizedArray<byte>& init_vector,
	        std::ostream& stream) :
		_in_fname(input_filename), _out_fname(output_filename),
		_key(key), _init_vector(init_vector), _key_type(key_type), _op(op), _mode(mode), _in_file_size(0)
	{
		_err = &stream;
	}

	~Cryptor();

	//check input files 
	int init();

	int process();

private:

	uint32 process_block(unsigned size);

	char* _in_fname;
	char* _out_fname;
	SizedArray<byte> _key;
	SizedArray<byte> _init_vector;

	KEY _key_type;
	OPERATION _op;
	MODE _mode;

	std::ifstream _in_file;
	std::ofstream _out_file;

	uint64 _in_file_size;


	std::ostream* _err;

	AES* core = NULL;
};


inline Cryptor::~Cryptor()
{
	/*if (_in_file)	fclose(_in_file);
	if (_out_file)	fclose(_out_file);
	*/

	if (_in_file.is_open())_in_file.close();
	if (_out_file.is_open())_out_file.close();

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
	_in_file.open(_in_fname, std::ios::in | std::ios::binary);
	if (!_in_file.is_open())
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

	_out_file.open(_out_fname, std::ios::out | std::ios::binary);
	if (!_out_file.is_open())
	{
		*_err << "Can't open file " << _out_fname << std::endl;
		return -5;
	}

	_in_file.seekg(0, _in_file.end);
	_in_file_size = _in_file.tellg();
	_in_file.seekg(0, _in_file.beg);

	if (!_in_file_size)
	{
		*_err << "Input file is empty" << std::endl;
		return -1;
	}

#ifdef _DEBUG
	*_err << "file size " << _in_file_size << '\n';
#endif // DEBUG



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

	if (_key_type == K24B)
	{
		SHA256 hasher;
		_key = hasher.get_hash(_key);
#ifdef _DEBUG
		*_err << "key sha256 hash (cut) |  " << K24B << "  |  ";
		for (uint32 i = 0; i < K24B; ++i)
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

	*_err << std::dec;

	core = new AES(_err);

	core->init(_mode, _op, _key._arr, _key_type, _init_vector._arr);

	return 0;
}

inline int Cryptor::process()
{
	if (core == NULL)
	{
		*_err << "core not initialized\n";
		return 4;
	}

	uint64 size = _in_file_size;

#ifdef PART_FILE_PROCESSING

	if (size < MEGABYTE)
	{
#ifdef _DEBUG
		*_err << "size < MEGA | " << size << std::endl;
#endif
		process_block(size);
	}
	else
	{
		uint32 full_blocks = size / MEGABYTE;
		uint32 remainder = size % MEGABYTE;

#ifdef _DEBUG
		*_err << "size > MEGA | " << size << std::endl<<"full blocks | "<<full_blocks<<"  remaind | "<<remainder<< std::endl;
#endif

		for (uint32 i = 0; i < full_blocks; i++)
		{
			int err = process_block(MEGABYTE);
			if (err<=0)return err;
		}
		int err = process_block(remainder);
		if (err<=0)return err;

	}
#else

#ifdef _DEBUG
	*_err << "size | " << size << std::endl;
#endif
	process_block(size);
#endif
	_out_file.flush();
	return 0;
}

inline uint32 Cryptor::process_block(unsigned size)
{
	byte* input = new byte[size];
	byte* out = new byte[size + 16];

	_in_file.read(reinterpret_cast<char*>(input), size);

#ifdef _DEBUG
	if (_in_file)
	{
		*_err << "size   |  " << size << '\n';
	}
	else
	{
		*_err << "error occured durind reading\n";
	}
#endif // DEBUG


	if (!_in_file)
	{
		*_err << "error occured durind reading\n";
		return -1;
	}

	int out_size;
	if (_op == ENCRYPT)
		out_size = core->encrypt_data(input, size, out);
	else
		out_size = core->decrypt_data(input, size, out);

	_out_file.write(reinterpret_cast<char*>(out), out_size);
	//_out_file.flush();

#ifdef _DEBUG
	*_err << "succes write to file | size " << out_size << '\n';
#endif // DEBUG


	if (!_out_file)
	{
		*_err << "error occured durind writing\n";
		return -2;
	}

	delete[] input;
	delete[] out;

	return out_size;
}

