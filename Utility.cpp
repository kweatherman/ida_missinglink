
// IDA plugin utility support
#include "StdAfx.h"
#include <tchar.h>
#include <winnt.h>

static ALIGN(16) TIMESTAMP performanceFrequency = 0;
struct OnUtilityInit
{
	OnUtilityInit()
	{
		LARGE_INTEGER large;
		QueryPerformanceFrequency(&large);
		performanceFrequency = (TIMESTAMP) large.QuadPart;
	}
} static _utilityInit;

qstring &GetVersionString(UINT32 version, qstring &version_string)
{
	version_string.sprnt("%u.%u.%u", GET_VERSION_MAJOR(MY_VERSION), GET_VERSION_MINOR(MY_VERSION), GET_VERSION_PATCH(MY_VERSION));
	VERSION_STAGE stage = GET_VERSION_STAGE(version);
	switch (GET_VERSION_STAGE(version))
	{
		case VERSION_ALPHA:	version_string += "-alpha";	break;
		case VERSION_BETA: version_string += "-beta"; break;
	};
	return version_string;
}

// Return high resolution floating elapsed seconds
TIMESTAMP GetTimestamp()
{
	LARGE_INTEGER large;
	QueryPerformanceCounter(&large);
	return ((TIMESTAMP) large.QuadPart / performanceFrequency);
}

void trace(__in LPCSTR format, ...)
{
	if (format)
	{
		va_list vl;
		char buffer[4096];	// 4096 is the OS buffer limit
		va_start(vl, format);
		vsprintf_s(buffer, sizeof(buffer), format, vl);
		va_end(vl);
		OutputDebugStringA(buffer);
	}
}

LPCSTR TimestampString(TIMESTAMP time, __out_bcount_z(64) LPSTR buffer)
{
	if(time >= HOUR)
		sprintf_s(buffer, 64, "%.2f hours", (time / (TIMESTAMP) HOUR));
	else
	if(time >= MINUTE)
		sprintf_s(buffer, 64, "%.2f minutes", (time / (TIMESTAMP) MINUTE));
	else
	if(time < (TIMESTAMP) 0.01)
		sprintf_s(buffer, 64, "%.2f ms", (time * (TIMESTAMP) 1000.0));
	else
		sprintf_s(buffer, 64, "%.2f seconds", time);
	return buffer;
}

LPSTR NumberCommaString(UINT64 n, __out_bcount_z(32) LPSTR buffer)
{
	int i = 0, c = 0;
	do
	{
		buffer[i] = ('0' + (n % 10)); i++;

		n /= 10;
		if ((c += (3 && n)) >= 3)
		{
			buffer[i] = ','; i++;
			c = 0;
		}

	} while (n);
	buffer[i] = 0;
	return _strrev(buffer);
}


// Get an error string for a GetLastError() code
LPSTR GetErrorString(DWORD lastError, __out_bcount_z(1024) LPSTR buffer)
{
	if (!FormatMessageA((FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS), NULL, lastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, 1024, NULL))
		strcpy_s(buffer, 1024, "Unknown");
	else
	{
		if (LPSTR lineFeed = strstr(buffer, "\r"))
			*lineFeed = 0;
	}
	return buffer;
}


// Dump byte range to debug output
void DumpData(LPCVOID ptr, int size, BOOL showAscii)
{
	#define RUN 16

	if(ptr && (size > 0))
	{
		__try
		{
			PBYTE pSrc = (PBYTE) ptr;
			char lineStr[256] = {0};
			int  uOffset = 0;

			// Create offset string based on input size
			char offsetStr[16];
			int iDigits = (int) strlen(_itoa(size, offsetStr, 16));
			sprintf(offsetStr, "[%%0%dX]: ", max(iDigits, 2));

			// Do runs
			char valueStr[(RUN + 1) * 3];
			while(size >= RUN)
			{
				sprintf(lineStr, offsetStr, uOffset);

				// Hex
				BYTE *pLine = pSrc;
				for(int i = 0; i < RUN; i++)
				{
					sprintf(valueStr, "%02X ", *pLine);
					strcat(lineStr, valueStr);
					++pLine;
				}

				// ASCII
				if (showAscii)
				{
					strcat(lineStr, "  ");

					pLine = pSrc;
					for (int i = 0; i < RUN; i++)
					{
						sprintf(valueStr, "%c", (*pLine >= ' ') ? *pLine : '.');
						strcat(lineStr, valueStr);
						++pLine;
					}
				}

				msg("%s\n", lineStr);
				uOffset += RUN, pSrc += RUN, size -= RUN;
			};

			// Final if not an even run line
			if(size > 0)
			{
				sprintf(lineStr, offsetStr, uOffset);

				// Hex
				BYTE *pLine = pSrc;
				for(int i = 0; i < size; i++)
				{
					sprintf(valueStr, "%02X ", *pLine);
					strcat(lineStr, valueStr);
					++pLine;
				}

				if (showAscii)
				{
					// Pad out line
					for (int i = 0; i < (RUN - size); i++) strcat(lineStr, "   ");
					strcat(lineStr, "  ");

					// ASCII
					pLine = pSrc;
					for (int i = 0; i < size; i++)
					{
						sprintf(valueStr, "%c", (*pLine >= ' ') ? *pLine : '.');
						strcat(lineStr, valueStr);
						++pLine;
					}
				}

				msg("%s\n", lineStr);
			}

		}__except(TRUE){}
	}
	#undef RUN
}



// ------------------------------------------------------------------------------------------------

// Print C SEH information
int ReportException(LPCSTR name, LPEXCEPTION_POINTERS nfo)
{
	msg(MSG_TAG "** Exception: 0x%08X @ 0x%llX, in %s()! **\n", nfo->ExceptionRecord->ExceptionCode, nfo->ExceptionRecord->ExceptionAddress, name);
	return EXCEPTION_EXECUTE_HANDLER;
}
