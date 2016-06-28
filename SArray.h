#pragma once
#include "defines.h"
#include <memory>

template<typename T> class SizedArray
{
public:
	T* _arr;
	uint32 size;

	SizedArray() {
		_arr = NULL;
		size = 0;
	}

	SizedArray(T* arr, uint32 sz) {
		_arr = arr;
		size = sz;
	}

	~SizedArray() {
		if (!_arr) delete _arr;
	}

	bool isEmpty() {
		return (_arr == NULL) || (size == 0);
	}

	/*operator byte*() {
		return (byte*)_arr;
	}*/

	void set(T* arr, int sz) {
		_arr = arr;
		size = sz;
	}

	SizedArray(const SizedArray& other) {
		size = other.size;
		_arr = other._arr;
	}

	SizedArray &operator=(SizedArray &other) {
		size = other.size;
		//std::memcpy(_arr, other._arr, size);
		_arr = other._arr;
		return *this;
	}

	SizedArray &operator=(char* other) {
		size = strlen(other);
		_arr = (T*)other;
		return *this;
	}
	T &operator[] (int i) {
		return _arr[i];
	}
};