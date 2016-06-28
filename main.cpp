#include "defines.h"
#include "getopt.h"
#include "cryptor.h"
#include "SArray.h"
#include <iostream>

using namespace std;

void help() {
	cout << "This program encrypt/decrypt file\n"
		<< "using AES with 128 bits key" << endl
		<< "Usage: AES [OPTION] [INPUT]" << endl
		<< "\tINPUT\t\tset input filename " << endl
		<< "\t-h\t\thelp menu (this screen)" << endl
		<< "\t-o filename\tset output filename" << endl
		<< "\t-e key\t\tencrypt file using key" << endl
		<< "\t-d key\t\tdecrypt file using key" << endl
		<< "\t-m mode\t\tencryption mode [ECB/CBC]" << endl
		<< "\t-i IV\t\tCBC initial vector" << endl
		<< "\t-k keylen\tkey length specification [128/192/256]" << endl;
}

int main(int argc, char** argv) {

	SizedArray<char> input_filename;
	SizedArray<char> output_filename;

	SizedArray<byte> key;
	SizedArray<byte> init_vector;

	KEY key_type = K16B;
	OPERATION op = NONE;
	MODE mode = ECB;

	/* check arguments */
	while (1) {
		int c = getopt(argc, argv, "-ho:e:d:m:i:k:");
		if (c == -1) break;

		switch (c) {

		case 'e':
			if (op == NONE) { op = ENCRYPT, key = optarg; }
			else { cout << "Only one operation [-e,-d] possible during a single run" << endl; return -2; }
			break;
		case 'd':
			if (op == NONE) { op = DECRYPT, key = optarg; }
			else { cout << "Only one operation [-e,-d] possible during a single run" << endl; return -3; }
			break;

		case 'm':
			if (optarg == "ecb" || optarg == "ECB")mode = ECB;
			else if (optarg == "cbc" || optarg == "CBC")	mode = CBC;
			break;

		case 'i': {init_vector = optarg; } break;

		case 'k':
			if (!strcmp(optarg, "128"))key_type = K16B;
			else if (!strcmp(optarg, "192"))key_type = K24B;
			else if (!strcmp(optarg, "256"))key_type = K32B;
			break;

		case 'h': help(); return 0;

		case 'o': output_filename = optarg;  break;
		case 1: input_filename = optarg;  break;

		}


#ifdef _DEBUG
		std::cerr << "Option " << ((c == 1) ? 'I' : (char)c) << " with " << optarg << endl;
#endif

	}

	if (input_filename.isEmpty()) { cout << "No input file cpecified" << endl; return -1; }
	if (op == NONE) { cout << "Operation not cpecified" << endl; return -1; }
	if (key.isEmpty()) { cout << "Key not cpecified" << endl; return -1; }

#ifdef _DEBUG
	std::cerr << "input data " << input_filename._arr << "\t" << op << "\t" << key._arr << "\t" << endl;
#endif

	/*initialize cryptor*/
	Cryptor crypt(input_filename, output_filename, op, key, key_type, mode, init_vector, std::cerr);
	int err = crypt.init();
	if (err != 0) return err;

#ifdef _DEBUG
	std::cerr << "crypt system init complete"<< endl;
#endif

	/*start crypting*/
	crypt.process();

#ifdef _DEBUG
	std::cerr << "end session" << '\n';
#endif // DEBUG

	return 0;
}