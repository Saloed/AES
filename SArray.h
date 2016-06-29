#pragma once
#include "defines.h"

template <typename T>
class SizedArray
{
public:
	T* _arr;
	uint64 size;

	SizedArray()
	{
		_arr = NULL;
		size = 0;
	}

	SizedArray(T* arr, uint32 sz)
	{
		_arr = arr;
		size = sz;
	}

	~SizedArray()
	{
		SADEL(_arr)
	}

	bool isEmpty()
	{
		return (_arr == NULL) || (size == 0);
	}

	/*operator byte*() {
		return (byte*)_arr;
	}*/

	void set(T* arr, int sz)
	{
		_arr = arr;
		size = sz;
	}

	SizedArray(const SizedArray& other)
	{
		size = other.size;
		_arr = new T[size];
		std::memcpy(_arr, other._arr, size * sizeof(T));
	}

	SizedArray& operator=(const SizedArray& other)
	{
		SADEL(_arr)
		size = other.size;
		_arr = new T[size];
		std::memcpy(_arr, other._arr, size * sizeof(T));
		return *this;
	}

	SizedArray& operator=(char* other)
	{
		size = strlen(other);
		_arr = new T[size];
		std::memcpy(_arr, other, size);
		return *this;
	}

	T& operator[](int i)
	{
		return _arr[i];
	}
};

