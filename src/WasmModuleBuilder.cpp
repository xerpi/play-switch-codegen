#include "WasmModuleBuilder.h"
#include <cassert>
#include "WasmDefs.h"

static void WriteName(Framework::CStream& stream, const char* str)
{
	auto length = strlen(str);
	assert(length < 0x80);
	stream.Write8(length);
	stream.Write(str, length);
}

void CWasmModuleBuilder::WriteSLeb128(Framework::CStream& stream, int32 value)
{
	bool more = true;
	while(more)
	{
		uint8 byte = (value & 0x7F);
		value >>= 7;
		if(
		    (value == 0 && ((byte & 0x40) == 0)) ||
		    (value == -1 && ((byte & 0x40) != 0)))
		{
			more = false;
		}
		else
		{
			byte |= 0x80;
		}
		stream.Write8(byte);
	}
}

void CWasmModuleBuilder::WriteULeb128(Framework::CStream& stream, uint32 value)
{
	while(1)
	{
		uint8 byte = (value & 0x7F);
		value >>= 7;
		if(value != 0)
		{
			byte |= 0x80;
		}
		stream.Write8(byte);
		if(value == 0)
		{
			break;
		}
	}
}

uint32 CWasmModuleBuilder::GetULeb128Size(uint32 value)
{
	uint32 size = 0;
	while(1)
	{
		uint8 byte = (value & 0x7F);
		value >>= 7;
		if(value != 0)
		{
			byte |= 0x80;
		}
		size++;
		if(value == 0)
		{
			break;
		}
	}
	return size;
}

void CWasmModuleBuilder::AddFunction(FUNCTION function)
{
	m_functions.push_back(std::move(function));
}

void CWasmModuleBuilder::WriteModule(Framework::CStream& stream)
{
	//We only support a single function at the moment
	assert(m_functions.size() == 1);

	stream.Write32(Wasm::BINARY_MAGIC);
	stream.Write32(Wasm::BINARY_VERSION);

	//Section "Type"
	{
		WriteSectionHeader(stream, Wasm::SECTION_ID_TYPE, 1 + 4 + 5);

		stream.Write8(2); //Type vector size

		//Type 0
		stream.Write8(0x60); //Func
		stream.Write8(1);    //Num params
		stream.Write8(Wasm::TYPE_I32);
		stream.Write8(0); //Num results

		//Type 1
		stream.Write8(0x60); //Func
		stream.Write8(1);    //Num params
		stream.Write8(Wasm::TYPE_I32);
		stream.Write8(1); //Num results
		stream.Write8(Wasm::TYPE_I32);
	}

	//Section "Import"
	{
		WriteSectionHeader(stream, Wasm::SECTION_ID_IMPORT, 0x20);

		stream.Write8(2); //Import vector size

		//Import 0
		WriteName(stream, "env");    //Import module name
		WriteName(stream, "memory"); //Import field name
		stream.Write8(Wasm::IMPORT_EXPORT_TYPE_MEMORY);
		stream.Write8(0x00); //Limit type 0
		stream.Write8(0x01); //Min

		//Import 1
		WriteName(stream, "env");
		WriteName(stream, "fctTable");
		stream.Write8(Wasm::IMPORT_EXPORT_TYPE_TABLE);
		stream.Write8(0x70); //Funcref
		stream.Write8(0x00); //Flags
		stream.Write8(0x01); //Initial
	}

	//Section "Function"
	{
		WriteSectionHeader(stream, Wasm::SECTION_ID_FUNCTION, 0x02);

		stream.Write8(1); //Function vector size

		//Function 0
		stream.Write8(0); //Signature index
	}

	//Section "Export"
	{
		WriteSectionHeader(stream, Wasm::SECTION_ID_EXPORT, 0x0A);

		stream.Write8(1); //Export vector size

		//Export 0
		WriteName(stream, "addTwo");
		stream.Write8(Wasm::IMPORT_EXPORT_TYPE_FUNCTION);
		stream.Write8(0); //Function index
	}

	//Section "Code"
	{
		const auto& function = m_functions[0];

		assert(function.localI32Count < 0x80);

		uint32 localDeclCount = (function.localI32Count == 0) ? 0 : 1;
		uint32 localDeclSize = (localDeclCount * 2) + 1;
		uint32 functionBodySize = function.code.size() + localDeclSize;

		uint32 sectionSize =
		    1 + //Vector size
		    GetULeb128Size(functionBodySize) +
		    functionBodySize;

		WriteSectionHeader(stream, Wasm::SECTION_ID_CODE, sectionSize);

		stream.Write8(1); //Function vector size

		//Function 0
		WriteULeb128(stream, functionBodySize); //Function body size
		WriteULeb128(stream, localDeclCount);   //Local declaration count
		if(function.localI32Count != 0)
		{
			WriteULeb128(stream, function.localI32Count); //Local type count
			stream.Write8(Wasm::TYPE_I32);
		}

		stream.Write(function.code.data(), function.code.size());
	}
}

void CWasmModuleBuilder::WriteSectionHeader(Framework::CStream& stream, uint8 sectionId, uint32 size)
{
	stream.Write8(sectionId);
	WriteULeb128(stream, size);
}
