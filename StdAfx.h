
// Common header
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shlobj_core.h>
#include <intrin.h>
#pragma intrinsic(memset, memcmp, memcpy, strcat, strcmp, strcpy, strlen, wcslen)

#include <algorithm>
#include <list>
#include <map>
#include <string>
#include <vector>

// IDA SDK
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#pragma warning(push)
#pragma warning(disable:4244) // "conversion from 'ssize_t' to 'int', possible loss of data"
#pragma warning(disable:4267) // "conversion from 'size_t' to 'uint32', possible loss of data"
#pragma warning(disable:4146) // "unary minus operator applied to unsigned type, result still unsigned"

#include <pro.h>
#include <idp.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <registry.hpp>
#pragma warning(pop)

#define MSG_TAG "MissingLink: "
#include "Utility.h"

#include <MinHook.h>

#include <WaitBoxEx.h>
#define REFRESH() { WaitBox::processIdaEvents(); }

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 1, 1, 0)
