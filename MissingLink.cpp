
// Gather indirect CALL and JMP instruction info
#include "StdAfx.h"
#include "Modules.h"
#include "hde32.h"
#include "hde64.h"

// JSON encoder
// https://github.com/nlohmann/json
#undef fgetc
#undef strtoull
#include "json.hpp"
using json = nlohmann::ordered_json;

#define EXTRA_INSTRUCTION_CHECKS
//#define DUMP_EXPORTS

// TODO: Max IDA string still 4096?
// TODO: Might want to limit to something smaller like 512 character'ish
#define COMMENT_STRING_LIMIT (4096-32)

// Error handling helpers for a "goto" style cleanup
#define ERROR_JMP(_reason) { msg(__FUNCTION__ ": ** " _reason " **\n"); goto exit; }
#define ERROR_FUNC_JMP(_api, _error) \
{ \
	char errorBuffer[1024]; \
	msg(__FUNCTION__ ": ** %s() failed, Error: 0x%X \"%s\" **", #_api, _error, GetErrorString(_error, errorBuffer)); \
	goto exit; \
}
#define ERROR_FUNC_ERRNO(_api, _error) \
{ \
	char errorBuffer[1024]; \
	strerror_s(errorBuffer, sizeof(errorBuffer), _error); \
	msg(__FUNCTION__ ": ** %s() failed, Error: 0x%X \"%s\" **", #_api, _error, errorBuffer); \
	goto exit; \
}

// Module array
static std::vector<Module> modules;

// Cached target model data
static UINT64 targetStart, targetEnd;
static UINT64 targetIatStart = 0, targetIatEnd = 0;
static LPCVOID targetImage = NULL;
static UINT64 targetIndex = -1;
static HANDLE waitBoxThread = NULL;
// Stats
static UINT64 indirectCalls = 0, indirectJmps = 0;
static UINT64 unmappedHits = 0;
static UINT32 overlaps = 0;
static UINT32 commentsPlaced = 0;

// To keep threads from overlapping multi-line logging
static CLock dumpLock;

// Indirect CALL/JMP tracking
// Optimization: Despite being a multi-level map, using a critical section lock, etc., appears to have little impact on capture speed even
// with large traces and high call counts. For problem cases, could look into replacing with more performant map container et al.
static std::map<UINT64 /*Src inst address*/, std::map<UINT64 /*Targ module address*/, std::map<UINT32 /*Module index*/, UINT64 /*Count*/>>> trackMap;
static CLock trackMapLock;


// Returns index of where an address belongs in the module space or -1 if it's outside of known
// Optimization: Has surprisingly little performance impact considering search is O(N)'ish here.
//  Probably the module array fits in the cache and then the fact the trace playback work is spread out over multiple
//  cores inside the MS TTD playback engine. Could be optimized for very large traces.
static UINT32 GetModuleByAddress(UINT64 address, __in TTD::Replay::Position &position)
{
	// TODO: Use an optimal search algorithm(s)
	UINT32 count = (UINT32) modules.size();
	for (UINT32 i = 0; i < count; i++)
	{
		Module &m = modules[i];
		if ((address >= m.start) && (address < m.end))
		{
			// If no overlap (normative case)
			if (!m.flags.overlap)
				return i;
			else
			{
				// Have overlap, need to match TTD position too
				if ((position >= m.load) && (position < m.unload))
					return i;
			}
		}
	}

	return -1;
}

// Track an indirect CALL/JMP hit
static void TrackHit(UINT64 ip, UINT64 target, __in TTD::Replay::ExecutionState const *threadView)
{
	const TTD::Replay::Position &position = threadView->GetPosition();
	UINT32 index = GetModuleByAddress(target, (TTD::Replay::Position&) position);

	// Track hits in unknown module spaces
	if (index == -1)
		unmappedHits++;

	trackMapLock.lock();
	{
		// 1st level: Track instruction pointers in our module
		auto ip_it = trackMap.find(ip);
		if (ip_it != trackMap.end())
		{
			// 2nd level: Track by target addresses
			auto target_it = ip_it->second.find(target);
			if (target_it != ip_it->second.end())
			{
				// 3rd level: Track branch hits per module
				// For the majority of the time module spaces are going to be a constant, but since they can be
				// loaded and unloaded at a same target address range, have to be considered temporal.
				auto index_it = target_it->second.find(index);
				if (index_it != target_it->second.end())
					index_it->second++;
				else
					target_it->second[index] = 1;
			}
			else
				ip_it->second[target][index] = 1;
		}
		else
			trackMap[ip][target][index] = 1;
	}
	trackMapLock.unlock();
}

// ------------------------------------------------------------------------------------------------
// Note: These callbacks from called from a thread pool, must be thread safe


#ifndef __EA64__
// On every CALL instruction
static void OnCall32(UINT64 lparm, Nirvana::GuestAddress target, Nirvana::GuestAddress return_address, __in TTD::Replay::ExecutionState const *threadView)
{
	// If the return is 0, its some sort of fallow-up return info where:
	// 'target' is the actual return address (follwing instruction past the CALL) and EIP (from GetProgramCounter()) is the address of the
	// last/preceding return instruction. Skip this data.
	if (return_address)
	{
		// Code in our module space?
		UINT64 eip = threadView->GetProgramCounter();
		if ((eip >= targetStart) && (eip < targetEnd))
		{
			// Yes, decode the CALL instruction
			UINT64 offset = (eip - targetStart);
			hde32s hs;
			UINT32 length = hde32_disasm((const PVOID) (((PBYTE) targetImage) + offset), &hs);
			if (length)
			{
				#ifdef EXTRA_INSTRUCTION_CHECKS
				if (hs.flags & (F_ERROR | F_ERROR_OPCODE | F_ERROR_LENGTH | F_ERROR_LOCK | F_ERROR_OPERAND))
				{
					dumpLock.lock();
					{
						TTD::Replay::Position current = threadView->GetPosition();
						msg(">> ** Error flags: CALL: EIP: %llX -> T: %llX,  R: %llX,  P: %llX:%llX, F: %08X **\n", eip, target, return_address, current.Sequence, current.Steps, hs.flags);
						DumpData(&hs, 16, FALSE);
					}
					dumpLock.unlock();
				}
				#endif

				// Indirect CALL?
				if (hs.flags & F_MODRM)
				{
					// Yes, pointer call?
					// Have to discern between import calls like "call ds:SetViewportOrgEx" that we don't want to track, and "call dword_6E825040" that we do want.
					if (hs.flags == (_32_F_DISP32 | F_MODRM))
					{
						if ((hs.modrm == 0x15) && (length == 6) && targetIatStart)
						{
							// Yes, skip if the pointer is inside the IAT pointer space
							UINT64 ptr = (UINT64) hs.disp.disp32;
							if ((ptr >= targetIatStart) && (ptr < targetIatEnd))
							{
								#if 0
								dumpLock.lock();
								{
									TTD::Replay::Position current = threadView->GetPosition();
									msg(">> CALL: EIP: %llX -> T: %llX,  R: %llX,  P: %llX:%llX, F: %08X **\n", eip, target, return_address, current.Sequence, current.Steps, hs.flags);
									DumpData(&hs, 16, FALSE);
								}
								dumpLock.unlock();
								#endif
								return;
							}
						}
					}

					#if 0
					dumpLock.lock();
					{
						TTD::Replay::Position current = threadView->GetPosition();
						msg(">> CALL: EIP: %llX -> T: %llX,  R: %llX,  P: %llX:%llX, F: %08X **\n", eip, target, return_address, current.Sequence, current.Steps, hs.flags);
						DumpData(&hs, 16, FALSE);
					}
					dumpLock.unlock();
					#endif

					TrackHit(eip, target, threadView);
					indirectCalls++;
				}
			}
			#ifdef EXTRA_INSTRUCTION_CHECKS
			else
			{
				dumpLock.lock();
				{
					TTD::Replay::Position current = threadView->GetPosition();
					msg("** Failed to decode: CALL: EIP: %llX -> T: %llX,  R: %llX, P: %llX:%llX **\n", threadView->GetProgramCounter(), target, return_address, current.Sequence, current.Steps);
				}
				dumpLock.unlock();
			}
			#endif
		}
	}
}

// On every indirect JMP instruction
static void OnIndirectJump32(UINT64 lparm, Nirvana::GuestAddress target, __in TTD::Replay::ExecutionState const *threadView)
{
	// Code in our module space?
	UINT64 eip = threadView->GetProgramCounter();
	if ((eip >= targetStart) && (eip < targetEnd))
	{
		// Yes, decode the JMP instruction
		UINT64 offset = (eip - targetStart);
		hde32s hs;
		UINT32 length = hde32_disasm((const PVOID) (((PBYTE) targetImage) + offset), &hs);
		if (length)
		{
			#ifdef EXTRA_INSTRUCTION_CHECKS
			if (hs.flags & (F_ERROR | F_ERROR_OPCODE | F_ERROR_LENGTH | F_ERROR_LOCK | F_ERROR_OPERAND))
			{
				dumpLock.lock();
				{
					TTD::Replay::Position current = threadView->GetPosition();
					msg(">> ** Error flags: JMP: EIP: %llX -> T: %llX,  P: %llX:%llX, F: %08X **\n", eip, target, current.Sequence, current.Steps, hs.flags);
					DumpData(&hs, 16, FALSE);
				}
				dumpLock.unlock();
			}
			#endif

			// Indirect JMP of interest?
			if (hs.flags & F_MODRM)
			{
				// Yes, pointer JMP?
				// Have to discern between import calls like "jmp ds:SetViewportOrgEx" that we don't want to track, and "jmp dword_6E825040" that we do want.
				if (hs.flags == (_32_F_DISP32 | F_MODRM))
				{
					if ((hs.modrm == 0x25) && (length == 6) && targetIatStart)
					{
						// Yes, skip if the pointer is inside the IAT pointer space
						UINT64 ptr = (UINT64) hs.disp.disp32;
						if ((ptr >= targetIatStart) && (ptr < targetIatEnd))
							return;
					}
				}

				#if 0
				dumpLock.lock();
				{
					TTD::Replay::Position current = threadView->GetPosition();
					msg(">> JMP: EIP: %llX -> T: %llX,  P: %llX:%llX, F: %08X\n", eip, target, current.Sequence, current.Steps, hs.flags);
					DumpData(&hs, 16, FALSE);
				}
				dumpLock.unlock();
				#endif

				TrackHit(eip, target, threadView);
				indirectJmps++;
			}
		}
		#ifdef EXTRA_INSTRUCTION_CHECKS
		else
		{
			dumpLock.lock();
			{
				TTD::Replay::Position current = threadView->GetPosition();
				msg("** Failed to decode: JMP: EIP: %llX -> T: %llX,  P: %llX:%llX **\n", threadView->GetProgramCounter(), target, current.Sequence, current.Steps);
			}
			dumpLock.unlock();
		}
		#endif
	}
}
#else
static void OnCall64(UINT64 lparm, Nirvana::GuestAddress target, Nirvana::GuestAddress return_address, __in TTD::Replay::ExecutionState const* threadView)
{
	// If the return is 0, its some sort of fallow-up return info where:
	// 'target' is the actual return address (follwing instruction past the CALL) and EIP (from GetProgramCounter()) is the address of the
	// last/preceding return instruction. Skip this data.
	if (return_address)
	{
		// Code in our module space?
		UINT64 rip = threadView->GetProgramCounter();
		if ((rip >= targetStart) && (rip < targetEnd))
		{
			// Yes, decode the CALL instruction
			UINT64 offset = (rip - targetStart);
			hde64s hs;
			UINT32 length = hde64_disasm((const PVOID) (((PBYTE) targetImage) + offset), &hs);
			if (length)
			{
				#ifdef EXTRA_INSTRUCTION_CHECKS
				if (hs.flags & (F_ERROR | F_ERROR_OPCODE | F_ERROR_LENGTH | F_ERROR_LOCK | F_ERROR_OPERAND))
				{
					dumpLock.lock();
					{
						TTD::Replay::Position current = threadView->GetPosition();
						msg(">> ** Error flags: CALL: RIP: %llX -> T: %llX,  R: %llX,  P: %llX:%llX, F: %08X **\n", rip, target, return_address, current.Sequence, current.Steps, hs.flags);
						DumpData(&hs, 21, FALSE);
					}
					dumpLock.unlock();
				}
				#endif

				// Indirect CALL?
				if (hs.flags & F_MODRM)
				{
					// Pointer call?
					// Have to discern between import calls like "call ds:SetViewportOrgEx" that we don't want to track, and "call dword_6E825040" that we do want.
					if (hs.flags == (_64_F_DISP32 | F_MODRM))
					{
						if ((hs.modrm == 0x15) && (length == 6) && targetIatStart)
						{
							// Skip if the pointer is inside the IAT space
							UINT64 ptr = (rip + (INT64) (*((PINT32) &hs.disp.disp32) + 6));
							if ((ptr >= targetIatStart) && (ptr < targetIatEnd))
								return;
						}
					}

					#if 0
					dumpLock.lock();
					{
						TTD::Replay::Position current = threadView->GetPosition();
						msg(">> CALL: RIP: %llX -> T: %llX,  R: %llX,  P: %llX:%llX, F: %08X **\n", rip, target, return_address, current.Sequence, current.Steps, hs.flags);
						DumpData(&hs, 21, FALSE);
					}
					dumpLock.unlock();
					#endif

					TrackHit(rip, target, threadView);
					indirectCalls++;
				}

				#if 0
				dumpLock.lock();
				{
					TTD::Replay::Position current = threadView->GetPosition();
					msg(">> CALL: RIP: %llX -> T: %llX,  R: %llX,  P: %llX:%llX, F: %08X **\n", rip, target, return_address, current.Sequence, current.Steps, hs.flags);
					DumpData(&hs, 21, FALSE);
				}
				dumpLock.unlock();
				#endif
			}
			#ifdef EXTRA_INSTRUCTION_CHECKS
			else
			{
				dumpLock.lock();
				{
					TTD::Replay::Position current = threadView->GetPosition();
					msg("** Failed to decode: CALL: RIP: %llX -> T: %llX,  R: %llX, P: %llX:%llX **\n", threadView->GetProgramCounter(), target, return_address, current.Sequence, current.Steps);
				}
				dumpLock.unlock();
			}
			#endif
		}
	}
}

static void OnIndirectJump64(UINT64 lparm, Nirvana::GuestAddress target, __in TTD::Replay::ExecutionState const* threadView)
{
	// Code in our module space?
	UINT64 rip = threadView->GetProgramCounter();
	if ((rip >= targetStart) && (rip < targetEnd))
	{
		// Yes, decode the JMP instruction
		UINT64 offset = (rip - targetStart);
		hde64s hs;
		UINT32 length = hde64_disasm((const PVOID) (((PBYTE) targetImage) + offset), &hs);
		if (length)
		{
			#ifdef EXTRA_INSTRUCTION_CHECKS
			if (hs.flags & (F_ERROR | F_ERROR_OPCODE | F_ERROR_LENGTH | F_ERROR_LOCK | F_ERROR_OPERAND))
			{
				dumpLock.lock();
				{
					TTD::Replay::Position current = threadView->GetPosition();
					msg(">> ** Error flags: JMP: RIP: %llX -> T: %llX,  P: %llX:%llX, F: %08X **\n", rip, target, current.Sequence, current.Steps, hs.flags);
					DumpData(&hs, 21, FALSE);
				}
				dumpLock.unlock();
			}
			#endif

			// Indirect JMP of interest?
			if (hs.flags & F_MODRM)
			{
				// Yes, pointer JMP?
				// Have to discern between import calls like "jmp ds:SetViewportOrgEx" that we don't want to track, and "jmp dword_6E825040" that we do want.
				if (hs.flags == (F_PREFIX_REX | _64_F_DISP32 | F_MODRM))
				{
					if ((hs.modrm == 0x25) && (length == 7) && targetIatStart)
					{
						// Skip if the pointer is inside the IAT space
						UINT64 ptr = (rip + (INT64) (*((PINT32) &hs.disp.disp32) + 7));
						if ((ptr >= targetIatStart) && (ptr < targetIatEnd))
							return;
					}
				}

				#if 0
				TTD::Replay::Position current = threadView->GetPosition();
				dumpLock.lock();
				{
					msg("\n>> JMP: RIP: %llX -> T: %llX,  P: %llX:%llX, F: %08X\n", rip, target, current.Sequence, current.Steps, hs.flags);
					DumpData(&hs, 21, FALSE);
				}
				dumpLock.unlock();
				#endif

				TrackHit(rip, target, threadView);
				indirectJmps++;
			}
		}
		#ifdef EXTRA_INSTRUCTION_CHECKS
		else
		{
			dumpLock.lock();
			{
				TTD::Replay::Position current = threadView->GetPosition();
				msg("** Failed to decode: JMP: RIP: %llX -> T: %llX,  P: %llX:%llX **\n", threadView->GetProgramCounter(), target, current.Sequence, current.Steps);
			}
			dumpLock.unlock();
		}
		#endif
	}
}
#endif

// ------------------------------------------------------------------------------------------------

// Clear/reset local working data
static void ClearData()
{
	modules.clear();
	trackMap.clear();

	targetStart = targetEnd = 0;
	targetIatStart = targetIatEnd = 0;
	targetImage = NULL;
	targetIndex = -1;

	indirectCalls = indirectJmps = 0;
	unmappedHits = 0;
	overlaps = 0;
	commentsPlaced = 0;
}

// ------------------------------------------------------------------------------------------------


// Tabulate source trace modules
BOOL TabulateModules(__in TTD::Replay::ReplayEngine *IReplayEngine, __in TTD::Replay::Cursor *ICursorView, __in LPCWCH targetModuleName)
{
	BOOL result = FALSE;

	UINT64 moduleLoadCount = IReplayEngine->GetModuleLoadedEventCount();
	UINT64 moduleUnloadCount = IReplayEngine->GetModuleUnloadedEventCount();
	std::map<LPCWCH, UINT64> module2index;

	//char numBuf2[32];
	//msg("Gathering %s module loads and %s unloads data..\n", NumberCommaString(moduleLoadCount, numBuf), NumberCommaString(moduleUnloadCount, numBuf2));
	if (!moduleLoadCount)
		ERROR_JMP("No module load events!");
	modules.reserve(moduleLoadCount);

	// Walk module load events
	const TTD::Replay::ModuleLoadedEvent *mles = IReplayEngine->GetModuleLoadedEventList();
	BOOL targetFound = FALSE;
	for (UINT64 i = 0; i < moduleLoadCount; i++)
	{
		const TTD::Replay::ModuleLoadedEvent &mle = mles[i];
		Module m;
		m.load = mle.pos;
		m.unload = TTD::Replay::Invalid;
		m.start = mle.t->base;
		m.end = (mle.t->base + mle.t->imageSize);
		m.path = mle.t->path;
		m.file = PathFindFileNameW(mle.t->path);

		// Is the desired target module?
		if (_wcsicmp(m.file, targetModuleName) == 0)
		{
			// Should only have one target module by name in the recording.
			// Although can happen with modules that get reloaded. Not currently supported.
			// Would need some mechanism, maybe just a count, passed as an argument to know which one to use.
			if (targetFound)
				ERROR_JMP("More than one of my short named modules exit in the trace");

			m.flags.isTarget = TRUE;
			targetFound = TRUE;
		}

		module2index[m.path] = modules.size();
		modules.push_back(m);

		if((i % 8) == 0)
			if(WaitBox::isUpdateTime())
				WaitBox::updateAndCancelCheck();
	}

	if (!targetFound)
		ERROR_JMP("My module not found in the trace module list!");
	REFRESH();

	// Walk module unload events
	if (moduleUnloadCount)
	{
		const TTD::Replay::ModuleUnloadedEvent *mues = IReplayEngine->GetModuleUnloadedEventList();
		for (UINT64 i = 0; i < moduleUnloadCount; i++)
		{
			// Should be known loaded
			const TTD::Replay::ModuleUnloadedEvent &mue = mues[i];
			auto it = module2index.find(mue.t->path);
			if (it != module2index.end())
			{
				// Set the unload position
				modules[it->second].unload = mue.pos;
			}
			else
			{
				// No
				// TODO: If this is a common occurrence, could handle it by assuming the start position and adding them to the array
				msg(" Unload module not known: ** B: " EAFORMAT ", S: %llX, P: %llX:%llX, M: \"%S\" **\n", mue.t->base, mue.t->imageSize, mue.pos.Sequence, mue.pos.Steps, mue.t->path);
			}

			if ((i % 8) == 0)
				if (WaitBox::isUpdateTime())
					WaitBox::updateAndCancelCheck();
		}
	}
	module2index.clear();

	// 2nd pass gather exports and determine module bitness
	UINT64 modulesFailed = 0;
	for (UINT64 i = 0; i < modules.size(); i++)
	{
		Module &m = modules[i];
		if (!ProcessModule(ICursorView, m))
			modulesFailed++;

		if (m.unload == TTD::Replay::Invalid)
		{
			msg(" * No TTD unload position for \"%S\" *\n", m.file);
			m.unload = TTD::Replay::EndOfTrace;
			m.flags.missingUnload = TRUE;
		}

		// Target should have a copy of it's module image
		if (m.flags.isTarget)
		{
			// TODO: Could byte copy over the IDB image to use instead
			if(!m.image)
				ERROR_JMP("Failed to get my module image");
		}

		if(i & 1)
			if (WaitBox::isUpdateTime())
				WaitBox::updateAndCancelCheck();
	}

	// Sort by ascending base address
	std::sort(modules.begin(), modules.end(), [](Module const &a, Module const &b) { return a.start < b.start; });

	// Dump any module address temporal overlaps
	// TODO: Add more permutations of modules overlapping and ones exacerbated by occasional missing unload positions
	msg("\nProcessomg overlaps..\n");
	REFRESH();
	const TTD::Replay::Position lastPos = IReplayEngine->GetLastPosition();
	UINT32 duplicates = 0;
	restart:;
	if (modules.size() > 1)
	{
		for (UINT64 i = 0; i < (modules.size() - 1); i++)
		{
			if (modules[i].end > modules[i + 1].start)
			{
				Module &ma = modules[i];
				Module &mb = modules[i+1];
				overlaps++;

				// Case where the same module is loaded, unloaded, and then loaded again at the same address
				// Same module?
				if (wcscmp(ma.path, mb.path) == 0)
				{
					ma.flags.duplicate = ma.flags.duplicate = TRUE;

					// Yes, same address?
					if (ma.start == mb.start)
					{
						// Yes, handle if one of the two has an invalid unload position
						// TODO: Probably something will fail if there is another module later in the same space
						if (ma.flags.missingUnload || mb.flags.missingUnload)
						{
							msg(" Merging overlapped duplicates:\n");
							TTD::Replay::Position load = min(ma.load, mb.load);
							TTD::Replay::Position unload;
							if (ma.flags.missingUnload && mb.flags.missingUnload)
								unload = lastPos;
							else
								unload = ((ma.flags.missingUnload == TRUE) ? mb.unload : ma.unload);

							msg(" [%llu] R: " EAFORMAT "-" EAFORMAT ", L: %016llX:%llX, U: %016llX:%llX, M: \"%S\"\n", i, ma.start, ma.end, ma.load.Sequence, ma.load.Steps, ma.unload.Sequence, ma.unload.Steps, ma.file);
							msg(" [%llu] R: " EAFORMAT "-" EAFORMAT ", L: %016llX:%llX, U: %016llX:%llX, M: \"%S\".\n", i + 1, mb.start, mb.end, mb.load.Sequence, mb.load.Steps, mb.unload.Sequence, mb.unload.Steps, mb.file);

							ma.load = load;
							ma.unload = unload;
							modules.erase(modules.begin() + (i + 1));
							goto restart;
						}
					}
				}

				ma.flags.overlap = mb.flags.overlap = TRUE;
				if (!ma.flags.shown)
				{
					msg(" Overlapped:\n");
					msg(" [%llu] R: " EAFORMAT "-" EAFORMAT ", L: %016llX:%llX, U: %016llX:%llX, M: \"%S\"\n", i, ma.start, ma.end, ma.load.Sequence, ma.load.Steps, ma.unload.Sequence, ma.unload.Steps, ma.file);
					msg(" [%llu] R: " EAFORMAT "-" EAFORMAT ", L: %016llX:%llX, U: %016llX:%llX, M: \"%S\".\n", i + 1, mb.start, mb.end, mb.load.Sequence, mb.load.Steps, mb.unload.Sequence, mb.unload.Steps, mb.file);
					ma.flags.shown = TRUE;
				}
			}

			if ((i % 8) == 0)
				if (WaitBox::isUpdateTime())
					WaitBox::updateAndCancelCheck();
		}
	}
	char numBuf[32];
	msg(" %s overlaps\n", NumberCommaString(overlaps, numBuf));

	// Dump the modules
	msg("\nModules:\n");
	char formatStr[128];
	int digits = (int) strlen(_itoa((int) modules.size(), formatStr, 10));
	sprintf(formatStr, "[%%0%du] R: %" EAFORMAT "-%" EAFORMAT ", L: %%016llX:%%llX, U: %%016llX:%%llX, F: %%X, EC: %%s, M: \"%%S\"\n", max(digits, 2));

	for (UINT32 i = 0; i < (UINT32) modules.size(); i++)
	{
		const Module &m = modules[i];
		msg(formatStr, i, m.start, m.end, m.load.Sequence, m.load.Steps, m.unload.Sequence, m.unload.Steps, m.flags.AsUint32, NumberCommaString(m.exports.size(), numBuf), m.path);

		#ifdef DUMP_EXPORTS
		for (auto const &exp: m.exports)
			msg("  " EAFORMAT " \"%s\"\n", exp.first, exp.second.c_str());
		#endif
	}
	if (modulesFailed)
		msg(" %s modules skipped.\n", NumberCommaString(modulesFailed, numBuf));

	// Get target index and dump info
	for (UINT32 i = 0; i < (UINT32) modules.size(); i++)
	{
		const Module &m = modules[i];
		if (m.flags.isTarget)
		{
			// Cache target module info
			targetIndex = i;
			targetStart = m.start, targetEnd = m.end;
			targetIatStart = m.iatStart, targetIatEnd = m.iatEnd;
			targetImage = m.image;

			msg("\nThis module index: %u\n", i);
			if (m.iatStart)
			{
				UINT64 iatStart = m.iatStart;
				UINT64 iatEnd = m.iatEnd;

				// Display base adjusted if it doesn't match (but still not reflected in the module list)
				UINT64 imagebase = (UINT64) get_imagebase();
				UINT64 adjustBase = ((targetStart == imagebase) ? 0 : imagebase);
				if (adjustBase)
				{
					iatStart = (adjustBase + (iatStart - targetStart));
					iatEnd = (adjustBase + (iatEnd - targetStart));
				}
				msg(" IAT section: %llX - %llX\n", iatStart, iatEnd);
			}
			else
				msg(" Has no IAT.\n");

			// Bitness should match this IDB
			#ifndef __EA64__
			if (!m.flags.is32bit)
				ERROR_JMP("The matching trace module is 64bit but this IDB is 32bit!");
			#else
			if (m.flags.is32bit)
				ERROR_JMP("The matching trace module is 32bit but this IDB is 64bit!");
			#endif

			break;
		}
	}
	result = TRUE;

	exit:;
	return result;
}


// Apply target branch comments
static void ApplyComments(BOOL useTag)
{
	// Need to adjust source addresses to the base if ours doesn't match the recorded one
	UINT64 imagebase = (UINT64) get_imagebase();
	UINT64 adjustBase = ((targetStart == imagebase) ? 0 : imagebase);

	// Iterate branch instruction addresses
	for (auto const &sourceToTarget: trackMap)
	{
		UINT64 source = sourceToTarget.first;
		if (adjustBase)
			source = (adjustBase + (source - targetStart));
		msg(EAFORMAT "\n", source);

		// TODO: Consider if source already has comment?
		//if (has_cmt(get_flags((ea_t) source)))

		// Optimization: The majority of the data is typically a single branch comment.
		// Not particularity slow as it is, but could be optimized my splinting into a single count and a multiple count path

		// Put target address(es) in list for sorting
		struct TARGET
		{
			UINT64 address; // Address in module
			UINT64 count;   // Branch hits at address
		};

		// Put addresses into silos by module index
		std::map<UINT32 /*Module index*/, std::list<TARGET>> silos;
		for (auto const &targetMap: sourceToTarget.second)
		{
			UINT64 address = targetMap.first;

			for (auto const &moduleMap: targetMap.second)
			{
				UINT32 index = moduleMap.first;
				UINT64 count = moduleMap.second;

				auto it = silos.find(index);
				if (it != silos.end())
					it->second.push_back({address, count});
				else
				{
					std::list<TARGET> list = {{address, count}};
					silos[index] = list;
				}
			}
		}

		// Put the silos in a list for sorting, putting local module address(es) always first
		struct TRGSET
		{
			UINT32 index;
			UINT64 totalCount;
			std::list<TARGET> list;
		};

		// Get locals first if exists
		TRGSET localSet = {0,0,};
		auto it = silos.find((UINT32) targetIndex);
		if (it != silos.end())
		{
			localSet.index = it->first;
			// Don't need count since we don't sort with it
			localSet.totalCount = 1;
			localSet.list = it->second;
			silos.erase(it);
		}

		// Add remaining module target sets
		std::list<TRGSET> trgset;
		for (auto const& silo : silos)
		{
			TRGSET ts = { silo.first, 0, silo.second };

			// Get total occurrence count for sorting
			for (auto const &target: ts.list)
				ts.totalCount += target.count;

			trgset.push_back(ts);
		}
		// Sort target addresses silos by descending occurrence count
		if (trgset.size() > 1)
			trgset.sort([](TRGSET const &a, TRGSET const &b) { return a.totalCount > b.totalCount; });

		// Insert local at front
		if (!localSet.list.empty())
			trgset.push_front(localSet);

		// Walk silo set by module
		std::string comment;
		if(useTag)
			comment = "#ML: ";
		BOOL cmntLimit = FALSE;
		while (!cmntLimit && !trgset.empty())
		{
			TRGSET ts = trgset.front();
			trgset.pop_front();

			// Sort target addresses by descending occurrence count
			if(ts.list.size() > 1)
				ts.list.sort([](TARGET const &a, TARGET const &b) { return a.count > b.count; });

			// Start next sub-comment with module name
			std::string subcmnt;
			BOOL group = FALSE;
			BOOL isLocal = (ts.index == (UINT32) targetIndex);

			// No module name nor grouping for locals
			if (!isLocal)
			{
				// Group if more than one address in the same module
				group = (ts.list.size() > 1);

				// Prefix with '*' if unmapped/unknown in lieu of known module name
				if (ts.index == -1)
				{
					if(group)
						subcmnt = "*[";
					else
						subcmnt = '*';
				}
				else
				{
					// If shortname ends with ".dll" nix it for terseness
					WCHAR fnameTrunc[_MAX_FNAME];
					LPCWCH filename = modules[ts.index].file;
					size_t len = wcslen(filename);
					if ((len > SIZESTR(".dll")) && (len < SIZESTR(fnameTrunc)))
					{
						if (_wcsicmp(&filename[len - SIZESTR(".dll")], L".dll") == 0)
						{
							wcsncpy_s(fnameTrunc, _countof(fnameTrunc), filename, (len - SIZESTR(".dll")));
							filename = fnameTrunc;
						}
					}

					qstring utf8;
					utf16_utf8(&utf8, filename);
					subcmnt = utf8.c_str();

					if (group)
						subcmnt += '[';
					else
						subcmnt += '!';
				}
			}

			// Walk address list
			for (auto const &tgs: ts.list)
			{
				if (ts.index == -1)
				{
					// If not mapped, won't have exports
					char buffer[32];
					sprintf_s(buffer, sizeof(buffer), "%llX,", tgs.address);
					subcmnt += buffer;
				}
				else
				{
					// Use export name instead of address if it exists
					LPCSTR name = NULL;
					if (modules[ts.index].FindExport(tgs.address, &name))
					{
						subcmnt += name;
						subcmnt += ',';
					}
					else
					{
						// Else address alone
						// Adjust local targets if not same base
						UINT64 address = tgs.address;
						if (adjustBase)
						{
							if(ts.index == (UINT32) targetIndex)
								address = (adjustBase + (address - targetStart));
						}

						char buffer[32];
						sprintf_s(buffer, sizeof(buffer), "%llX,", address);
						subcmnt += buffer;
					}
				}

				// If we hit comment limit, bail out
				if ((comment.size() + subcmnt.size()) > COMMENT_STRING_LIMIT)
				{
					subcmnt.pop_back();
					cmntLimit = TRUE;
					break;
				}
			}

			if (group && !cmntLimit)
			{
				subcmnt.pop_back();
				subcmnt += "],";
			}

			comment += subcmnt;
		};

		// Nix trailing ','
		if(comment.back() == ',')
			comment.pop_back();

		// If hit the comment length limit, tag it as such
		if (cmntLimit)
			comment += " ...";

		// Place comment
		set_cmt((ea_t) source, "", TRUE);
		set_cmt((ea_t) source, comment.c_str(), FALSE);
		commentsPlaced++;
	}
}


// Optionally save the data to a JSON DB for post analysis
static BOOL SaveJsonDB(LPCSTR jsonDbPath)
{
	if (!(indirectCalls || indirectJmps))
	{
		msg("\nNo JSON data to save.\n");
		return TRUE;
	}

	BOOL result = FALSE;
	msg("\nSaving JSON DB to: \"%s\"\n", jsonDbPath);
	REFRESH();

	// Our index into the module array
	json j;
	j["target_index"] = targetIndex;

	// Store module array
	{
		json moduleArray = json::array();
		for (UINT32 i = 0; i < (UINT32)modules.size(); i++)
		{
			Module &m = modules[i];

			json mod;
			mod["index"] = i;
			mod["start"] = m.start;
			mod["end"] = m.end;

			qstring pathUtf8;
			utf16_utf8(&pathUtf8, m.path);
			mod["path"] = pathUtf8.c_str();

			mod["flags"] = m.flags.AsUint32;

			mod["load"] = json::array({ m.load.Sequence, m.load.Steps });
			mod["unload"] = json::array({ m.unload.Sequence, m.unload.Steps });

			// Exports [address, "name"]
			json exportsArray = json::array();
			for (auto const& exprt : m.exports)
				exportsArray.push_back(json::array({ exprt.first, exprt.second }));
			mod["exports"] = exportsArray;

			moduleArray.push_back(mod);
		}
		j["modules"] = moduleArray;
	}

	// Calls data
	// std::map<UINT64 /*Src inst address*/, std::map<UINT64 /*Targ module address*/, std::map<UINT32 /*Module index*/, UINT64 /*Count*/>>> trackMap;
	json branchArray = json::array();
	for (auto const &e: trackMap)
	{
		json entryArray = json::array();
		{
			// Source address
			entryArray.push_back(e.first);

			json targetArray = json::array();
			{
				for (auto const &ts : e.second)
				{
					json targetEntryArray = json::array();
					{
						// Target address
						targetEntryArray.push_back(ts.first);

						// Array of [module index, count]
						json modCountArray = json::array();
						for (auto const &mc : ts.second)
						{
							modCountArray.push_back(json::array({ mc.first, mc.second}));
						}
						targetEntryArray.push_back(modCountArray);
					}
					targetArray.push_back(targetEntryArray);
				}
			}
			entryArray.push_back(targetArray);
		}
		branchArray.push_back(entryArray);
	}
	j["branches"] = branchArray;

	// Save to file
	std::string str = j.dump(4);
	FILE *fp = NULL;
	errno_t st = fopen_s(&fp, jsonDbPath, "wbS");
	if (st != 0)
		ERROR_FUNC_ERRNO(fopen_s, st);
	fwrite(str.c_str(), str.size(), 1, fp);
	fputs("\n", fp);

	exit:;
	if (fp)
	{
		fclose(fp);
		fp = NULL;
	}
	return result;
}


static void progressCallback(UINT64, TTD::Replay::Position const&)
{
	// Gets called by the main thread only, so it can be safely used to update the wait box
	static int checkCounter = 0;
	if ((++checkCounter % 4) == 0)
	{
		//trace(" ** TID: %X **\n", GetCurrentThreadId());
		if (WaitBox::isUpdateTime())
			WaitBox::updateAndCancelCheck();
	}
}

// Load trace file and apply it to this IDB
BOOL ProcessTraceFile(LPCSTR tracefile, LPCSTR winDbgXPath, LPCSTR jsonDbPath, BOOL useTag)
{
	BOOL result = FALSE;
	TTD::Replay::ReplayEngine *IReplayEngine = NULL;
	TTD::Replay::Cursor *ICursorView = NULL;

	try
	{
		// Initialize and create the replay engine class instance
		qwstring wDbgXpath;
		if (!utf8_utf16(&wDbgXpath, winDbgXPath))
			ERROR_JMP("utf8_utf16() failed");

		HRESULT hr = TTD::CreateReplayEngine(wDbgXpath.c_str(), &IReplayEngine);
		if (hr != S_OK)
			ERROR_FUNC_JMP(CreateReplayEngine, hr);

		// Load the trace file
		WaitBox::show("Missing link", "Loading trace..");
		WaitBox::updateAndCancelCheck(-1);
		//msg("TID: %X\n", GetCurrentThreadId());

		msg("Loading trace: \"%s\"..\n", tracefile);
		qwstring wpath;
		if (!utf8_utf16(&wpath, tracefile))
			ERROR_JMP("utf8_utf16() failed");
		REFRESH();

		// No callback in here so we can't update our wait box, IDA will be unresponsive
		TIMESTAMP loadStart = GetTimestamp();
		if (!IReplayEngine->Initialize(wpath.c_str()))
			ERROR_FUNC_JMP(Initialize, HRESULT_FROM_WIN32(GetLastError()));
		char timeBuffer[64];
		msg(" Took %s.\n", TimestampString((GetTimestamp() - loadStart), timeBuffer));
		WaitBox::updateAndCancelCheck();

		// Instance a Cursor for the trace
		ICursorView = IReplayEngine->NewCursor(TTD::Replay::Cursor::IID_ICursorView);
		if (hr != S_OK)
			ERROR_FUNC_JMP(NewCursor, hr);

		const TTD::Replay::Position firstPos = IReplayEngine->GetFirstPosition();
		const TTD::Replay::Position lastPos = IReplayEngine->GetLastPosition();
		// Must do at least one set position call to initialize the else the state reads will be invalid.
		ICursorView->SetPosition(firstPos);

		msg("First position: %llX:%llX, last: %llX:%llX.\n", firstPos.Sequence, firstPos.Steps, lastPos.Sequence, lastPos.Steps);
		char numBuf[32];
		msg("Thread count: %s\n", NumberCommaString(IReplayEngine->GetThreadCount(), numBuf));

		// Get current IDB filename as module target name
		char idbFilename[_MAX_FNAME] = { 0 };
		get_root_filename(idbFilename, SIZESTR(idbFilename));
		qwstring widbFilename;
		if (!utf8_utf16(&widbFilename, idbFilename))
			ERROR_JMP("utf8_utf16() failed");
		LPCWCH targetModuleName = widbFilename.c_str();
		msg("This module: \"%S\"\n\n", targetModuleName);

		// Reset local data
		ClearData();

		// Tabulate modules
		msg("Tabulating trace modules..\n");
		WaitBox::setLabelText("Tabulating modules..");
		WaitBox::updateAndCancelCheck();
		REFRESH();
		if (!TabulateModules(IReplayEngine, ICursorView, targetModuleName))
			goto exit;

		// Set CALL and indirect JMP callbacks
		#ifndef __EA64__
		ICursorView->SetCallReturnCallback(OnCall32, 0);
		ICursorView->SetIndirectJumpCallback(OnIndirectJump32, 0);
		#else
		ICursorView->SetCallReturnCallback(OnCall64, 0);
		ICursorView->SetIndirectJumpCallback(OnIndirectJump64, 0);
		#endif

		// Traverse forward over the entire trace of the target module space..
		msg("\nTraversing trace..\n");
		WaitBox::setLabelText("Traversing trace..");
		WaitBox::updateAndCancelCheck();
		REFRESH();

		// Trace from our module load to it's unload on the time line
		TIMESTAMP startTime = GetTimestamp();
		//ICursorView->SetReplayProgressCallback(progressCallback, 0);
		ICursorView->SetPosition(modules[targetIndex].load);
		TTD::Replay::Cursor::ReplayResult replayResult = ICursorView->ReplayForward(modules[targetIndex].unload, -1);

		msg(" Traversed %s TTD steps in %s\n", NumberCommaString(replayResult.StepCount, numBuf), TimestampString((GetTimestamp() - startTime), timeBuffer));
		msg("%s indirect CALLs and %s indirect JMPs found in this module.\n", NumberCommaString(indirectCalls, numBuf), NumberCommaString(indirectJmps, timeBuffer));
		msg("Unmapped target hits: %s.\n", NumberCommaString(unmappedHits, numBuf));
		WaitBox::updateAndCancelCheck();

		msg("\nApplying comments..\n");
		WaitBox::setLabelText("Applying comments..");
		WaitBox::updateAndCancelCheck();
		REFRESH();
		TIMESTAMP commentsStart = GetTimestamp();
		ApplyComments(useTag);
		msg(" Placed %s comments in %s.\n", NumberCommaString(commentsPlaced, numBuf), TimestampString((GetTimestamp() - commentsStart), timeBuffer));

		// Optionally save JSON DB data file
		if(jsonDbPath)
			SaveJsonDB(jsonDbPath);

		result = TRUE;
	}
	CATCH("ProcessTraceFile()");

	exit:;
	// Clean up
	if (ICursorView)
	{
		ICursorView->Destroy();
		ICursorView = NULL;
	}

	if (IReplayEngine)
	{
		IReplayEngine->Destroy();
		IReplayEngine = NULL;
	}

	// Unload the TTD replay DLLs to reset their state for next invocation
	FreeLibrary(GetModuleHandleA("TTDReplayCPU.dll"));
	FreeLibrary(GetModuleHandleA("TTDReplay.dll"));

	ClearData();
	WaitBox::hide();
	return result;
}