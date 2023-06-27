
// TTD module support
#pragma once
#include <DbgTtd.h>

// Module container with TTD lifetime info
struct Module
{
	TTD::Replay::Position load;	  // Module load position
	TTD::Replay::Position unload; // Module unload position

	UINT64 start;	// Start/base address
	UINT64 end;		// End address

	LPCWCH path;	// Full path (OS virtualized, no "SysWOW64" paths)
	LPCWCH file;	// Just file short name with extension

	// Exported functions from this module
	std::map<UINT64 /*address*/, std::string /*name*/> exports;

	union
	{
		struct
		{
			UINT32 is32bit: 1;			// Module is 32bit, else it's 64bit
			UINT32 isTarget: 1;			// Is the target module
			UINT32 missingUnload: 1;	// Missing a module unload event
			UINT32 overlap: 1;			// Overlaps one or more other modules (merges are not flagged)
			UINT32 duplicate: 1;		// Has a duplicate short file name
			UINT32 shown: 1;			// Already dumped in the overlap test code
		};
		UINT32 AsUint32;
	} flags;

	// Target module specific
	LPCVOID image;	 // Internal memory buffer
	UINT64 iatStart; // IAT start or 0 if none
	UINT64 iatEnd;	 // IAT end

	// -------------------------------------------------------
	// Return a modules export name by address if it exists
	BOOL FindExport(UINT64 address, __out LPCSTR *name)
	{
		auto it = exports.find(address);
		if (it != exports.end())
		{
			*name = it->second.c_str();
			return TRUE;
		}
		return FALSE;
	}

	void clear()
	{
		exports.clear();

		if (image)
			delete image;
		image = NULL;		
	}

	Module()
	{
		flags.AsUint32 = 0;
		image = NULL;
		iatStart = iatEnd = 0;
	}
	~Module()
	{ 
		path = file = NULL;
		// Can't call, we want to keep internal data until explicitly not needed
		//clear(); 
	}
};

BOOL ProcessModule(__in TTD::Replay::Cursor *ICursorView, __inout Module &module);