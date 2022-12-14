#pragma once

#include "Test.h"
#include "MemoryFunction.h"

class CCall64Test : public CTest
{
public:
	virtual				~CCall64Test() = default;

	static void			PrepareExternalFunctions();

	void				Compile(Jitter::CJitter&);
	void				Run();

private:
	struct CONTEXT
	{
		uint64			value0;
		uint64			value1;

		uint64			result0;
		uint64			result1;
		uint64			result2;
		uint64			result3;
	};

	static uint64		Add64(uint64, uint64);
	static uint64		Sub64(uint64, uint64);
	static uint64		AddMul64(uint32, uint64, uint64);
	static uint64		AddMul64_2(uint32, uint64, uint32);

	CMemoryFunction		m_function;
};
