
// TTD module support
#include "StdAfx.h"
#include "Modules.h"


// Given an RVA, look up the section header that encloses it and return a pointer to its IMAGE_SECTION_HEADER
template <class T> PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(UINT32 rva, T* ntHeader)
{
	PIMAGE_SECTION_HEADER secHead = IMAGE_FIRST_SECTION(ntHeader);
	for (UINT32 i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, secHead++)
	{
		UINT32 size = secHead->Misc.VirtualSize;
		if (!size)
			size = secHead->SizeOfRawData;

		// Is the RVA within this section?
		if ((rva >= secHead->VirtualAddress) && (rva < (secHead->VirtualAddress + size)))
			return secHead;
	}
	return NULL;
}

template <class T> LPVOID GetPtrFromRVA(UINT32 rva, T* ntHeader, PVOID imageBase)
{
	if (PIMAGE_SECTION_HEADER secHead = GetEnclosingSectionHeader(rva, ntHeader))
		return((PVOID) (((UINT_PTR) imageBase) + rva));
	else
		return NULL;
}


// Parse module exports from in-memory PE header
static void ParseExports(PBYTE base, __inout Module &module)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) base;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		msg(" * Module \"%S\" in memory has bad DOS header signature *\n", module.file);
		return;
	}

	PIMAGE_NT_HEADERS32 ntHeaderAny = (PIMAGE_NT_HEADERS32) (base + dosHeader->e_lfanew);
	if (ntHeaderAny->Signature != LOWORD(IMAGE_NT_SIGNATURE))
	{
		msg(" * Module \"%S\" in memory has bad NT header signature *\n", module.file);
		return;
	}

	if (ntHeaderAny->FileHeader.SizeOfOptionalHeader == 0)
		return;

	// x86
	if (ntHeaderAny->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		module.flags.is32bit = TRUE;

		PIMAGE_NT_HEADERS32 ntHeader32 = ntHeaderAny;
		// TODO: Allow the TTD image base, or use the default/assumed one?
		//UINT64 VirtaulBase = 0x10000000;
		// Note: To get the actual, not assumed default, static base address, would have to read it from the original module off disk
		// since the loaded one's PE header is modified post load.
		UINT64 VirtaulBase = (UINT64) ntHeader32->OptionalHeader.ImageBase;

		DWORD exportsRva = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY) GetPtrFromRVA(exportsRva, ntHeader32, base);
		if (exportDir)
		{
			PUINT functions = (PUINT) GetPtrFromRVA(exportDir->AddressOfFunctions, ntHeader32, base);
			PWORD ordinals  = (PWORD) GetPtrFromRVA(exportDir->AddressOfNameOrdinals, ntHeader32, base);
			PUINT names     = (PUINT) GetPtrFromRVA(exportDir->AddressOfNames, ntHeader32, base);
			UINT32 functionCount = exportDir->NumberOfFunctions;
			UINT32 nameCount = exportDir->NumberOfNames;

			for (UINT32 i = 0; i < functionCount; i++)
			{
				UINT32 entryPointRVA = functions[i];
				if (!entryPointRVA)
					continue;

				for (UINT32 j = 0; j < nameCount; j++)
				{
					if (ordinals[j] == i)
					{
						LPSTR name = (LPSTR) GetPtrFromRVA(names[j], ntHeader32, base);
						module.exports[VirtaulBase + entryPointRVA] = name;
						break;
					}
				}
			}
		}
	}
	else
	// AMD64
	if (ntHeaderAny->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64) ntHeaderAny;

		//UINT64 VirtaulBase = 0x180000000;
		UINT64 VirtaulBase = ntHeader64->OptionalHeader.ImageBase;

		DWORD exportsRva = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY) GetPtrFromRVA(exportsRva, ntHeader64, base);
		if (exportDir)
		{
			PUINT functions = (PUINT) GetPtrFromRVA(exportDir->AddressOfFunctions, ntHeader64, base);
			PWORD ordinals  = (PWORD) GetPtrFromRVA(exportDir->AddressOfNameOrdinals, ntHeader64, base);
			PUINT names     = (PUINT) GetPtrFromRVA(exportDir->AddressOfNames, ntHeader64, base);
			UINT32 functionCount = exportDir->NumberOfFunctions;
			UINT32 nameCount = exportDir->NumberOfNames;

			for (UINT32 i = 0; i < functionCount; i++)
			{
				UINT32 entryPointRVA = functions[i];
				if (!entryPointRVA)
					continue;

				for (UINT32 j = 0; j < nameCount; j++)
				{
					if (ordinals[j] == i)
					{
						LPSTR name = (LPSTR) GetPtrFromRVA(names[j], ntHeader64, base);
						module.exports[VirtaulBase + entryPointRVA] = name;
						break;
					}
				}
			}
		}
	}
	else
		msg(" * Module \"%S\" in memory has unsupported machine type: 0x%X *\n", module.file, ntHeaderAny->FileHeader.Machine);
}


// Get PE IAT section extents if it exists
static void GetIatInfo(PBYTE base, __inout Module &module)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) base;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	PIMAGE_NT_HEADERS32 ntHeaderAny = (PIMAGE_NT_HEADERS32) (base + dosHeader->e_lfanew);
	if (ntHeaderAny->Signature != LOWORD(IMAGE_NT_SIGNATURE))
		return;

	if (ntHeaderAny->FileHeader.SizeOfOptionalHeader == 0)
		return;

	// x86
	if (ntHeaderAny->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		PIMAGE_NT_HEADERS32 ntHeader32 = ntHeaderAny;
		if (ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size)
		{
			DWORD importsRva = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
			module.iatStart = (module.start + importsRva);
			module.iatEnd = (module.iatStart + ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
		}
	}
	else
	// AMD64
	if (ntHeaderAny->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64) ntHeaderAny;
		if (ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size)
		{
			DWORD importsRva = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
			module.iatStart = (module.start + importsRva);
			module.iatEnd = (module.iatStart + ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
		}
	}
}


// Determine bitness and gather module exports
// Returns TRUE on success
BOOL ProcessModule(__in TTD::Replay::Cursor *ICursorView, __inout Module &module)
{
	BOOL result = FALSE;
	TTD::TBufferView modBuff = { NULL, 0};

	try
	{
		// Move to where this module is loaded into memory
		ICursorView->SetPosition(module.load);

		// Get the module's memory
		size_t moduleSize = (module.end - module.start);
		modBuff.buffer = new(std::nothrow) BYTE[moduleSize];
		if (!modBuff.buffer)
		{
			msg(" ** Failed to allocate module \"%S\" buffer of 0x%llX size, export parsing skipped **\n", module.file, moduleSize);
			goto exit;
		}
		modBuff.size = moduleSize;

		TTD::Replay::MemoryBuffer memBuff = ICursorView->QueryMemoryBuffer(module.start, &modBuff, TTD::Replay::DefaultMemoryPolicy);
		if (memBuff.size < moduleSize)
		{
			msg(" * Got only 0x%llX of 0x%llX bytes for module \"%S\", export parsing skipped *\n", memBuff.size, moduleSize, module.file);
			goto exit;
		}

		// Parse exports from PE export header
		ParseExports((PBYTE) modBuff.buffer, module);

		// Extra data for target module
		if (module.flags.isTarget)
		{
			// Save the image for later dissembly
			module.image = (PBYTE) modBuff.buffer;

			// Save sections info for resolving direct pointer calls
			GetIatInfo((PBYTE) modBuff.buffer, module);
		}
		result = TRUE;
	}
	CATCH()

	exit:;
	if (modBuff.buffer && !module.flags.isTarget)
	{
		delete modBuff.buffer;
		modBuff.buffer = NULL;
	}

	return result;
}

