
//----------------------------------------------------------------------------
//
// Time Travel Debugger (TTD) engine interface
// IDA Pro plugin version
//----------------------------------------------------------------------------
#pragma once

#include <string>

// Place holder for virtual class members until if/when they are populated
#define PLACE_HOLDER(_name) virtual void _name() {}

namespace Nirvana
{
	// Process address type
	typedef UINT64 GuestAddress;
};

namespace TTD
{
	struct SystemInfo;

	// Query memory output buffer container
	// struct TTD::TBufferView
	struct TBufferView
	{
		PVOID buffer;
		UINT64 size;
	};

	// Error output callbacks for internal TTD errors
	class ErrorReporting
	{
	public:
		virtual ~ErrorReporting() {}
		virtual void PrintError(const std::string &error) {}
		virtual void VPrintError(LPCSTR format, ...) {}
	};
	static_assert(sizeof(ErrorReporting) == sizeof(ULONG_PTR), "Should be equal the size of a vftable");

	namespace Replay
	{
		// TTD cursor position
		// struct TTD::Replay::Position
		struct Position
		{
			UINT64 Sequence;
			UINT64 Steps;

			bool operator < (const Position &rhs)
			{
				if (Sequence == rhs.Sequence)
					return (Steps < rhs.Steps);
				else
					return (Sequence < rhs.Sequence);
			}

			bool operator <= (const Position &rhs)
			{
				if (Sequence == rhs.Sequence)
				{
					if (Steps == rhs.Steps)
						return true;
					else
						return (Steps < rhs.Steps);
				}
				else
					return (Sequence < rhs.Sequence);
			}

			bool operator > (const Position &rhs)
			{
				if (Sequence == rhs.Sequence)
					return (Steps > rhs.Steps);
				else
					return (Sequence > rhs.Sequence);
			}

			bool operator >= (const Position &rhs)
			{
				if (Sequence == rhs.Sequence)
				{
					if (Steps == rhs.Steps)
						return true;
					else
						return (Steps > rhs.Steps);
				}
				else
					return (Sequence > rhs.Sequence);
			}

			bool operator == (const Position &rhs)
			{
				return ((Sequence == rhs.Sequence) && (Steps == rhs.Steps));
			}
		};
		static const Position Min = { 0, 0 };
		static const Position Max = { 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFE };
		static const Position Invalid = { (UINT64) -1, (UINT64) -1 };
		// "A position of FFFFFFFFFFFFFFFE:0 indicates the end of the trace."
		// Seen with ModuleUnload events on process shutdown
		static const Position EndOfTrace = {0xFFFFFFFFFFFFFFFE, 0};

		enum DebugModeType
		{
			DefaultMode = 0,
		};

		typedef UINT32 UniqueThreadId;	// TTD::Replay::UniqueThreadId

		// struct TTD::Replay::ThreadInfo
		struct ThreadInfo
		{
			UINT32 index; // Internal thread index
			UINT32 threadId;
			// TODO: Appears to have a larger memory block, might have more values
		};

		// struct TTD::Replay::Module
		struct Module
		{
			LPCWCH path;
			size_t path_len;
			Nirvana::GuestAddress base;
			size_t imageSize;
			DWORD checkSum;
			WORD timestampEnd;
		};

		// struct TTD::Replay::ModuleInstance
		struct ModuleInstance
		{
			Module *module;
			UINT64 number;
			UINT64 unk; // Always equal to -2
		};


		// Exception event container
		struct Exception
		{
			PVOID	unk;
			DWORD	firstChance;

			// EXCEPTION_RECORD64
			DWORD	ExceptionCode;
			DWORD	ExceptionFlags;
			DWORD64	ExceptionRecord;
			DWORD64	ExceptionAddress;
			DWORD	NumberParameters;
			DWORD	__unusedAlignment;
			DWORD64	ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
		};

		// An event type is linked to a thread or a module
		// It will inform on start and end position of the event
		template<typename T> struct BaseEvent
		{
			Position pos;
			T t;
		};

		using ModuleLoadedEvent     = BaseEvent<Module*>;		// struct TTD::Replay::ModuleLoadedEvent
		using ModuleUnloadedEvent   = BaseEvent<Module*>;		// struct TTD::Replay::ModuleUnloadedEvent
		using ThreadCreatedEvent    = BaseEvent<ThreadInfo*>;	// struct TTD::Replay::ThreadCreatedEvent
		using ThreadTerminatedEvent = BaseEvent<ThreadInfo*>;	// struct TTD::Replay::ThreadTerminatedEvent
		using ExceptionEvent        = BaseEvent<Exception>;		// struct TTD::Replay::ExceptionEvent

		typedef UINT32 RecordingType;	// enum TTD::Replay::RecordingType
		typedef UINT32 IndexStatus;		// enum TTD::Replay::IndexStatus

		class Cursor;

		// const TTD::Replay::ReplayEngine::`vftable'{for `TTD::Replay::IReplayEngine'}
		// Referenced as "IReplayEngine" in other classes, as "IReplayEngineView" in the extension DLL
		class ReplayEngine
		{
		public:
			// [00]: public: virtual void const * TTD::Replay::ReplayEngine::UnsafeAsInterface(struct _GUID const &)const
			PLACE_HOLDER(UnsafeAsInterface_const);

			// [01]: public: virtual void * TTD::Replay::ReplayEngine::UnsafeAsInterface(struct _GUID const &)
			PLACE_HOLDER(UnsafeAsInterface);

			// [02]: public: virtual enum Nirvana::GuestAddress TTD::Replay::ReplayEngine::GetPebAddress()const
			virtual Nirvana::GuestAddress GetPebAddress() const;

			// [03]: public: virtual struct TTD::SystemInfo const & TTD::Replay::ReplayEngine::GetSystemInfo()const
			//virtual SystemInfo const& GetSystemInfo() const;
			virtual SystemInfo const *GetSystemInfo() const;

			// [04]: public: virtual struct TTD::Replay::Position const & TTD::Replay::ReplayEngine::GetFirstPosition()const
			virtual Position const& GetFirstPosition() const;

			// [05]: public: virtual struct TTD::Replay::Position const & TTD::Replay::ReplayEngine::GetLastPosition()const
			virtual Position const& GetLastPosition() const;

			// [06]: public: virtual struct TTD::Replay::Position const & TTD::Replay::ReplayEngine::GetFirstPosition()const
			PLACE_HOLDER(GetFirstPosition_duplicate);

			// [07]: public: virtual enum TTD::Replay::RecordingType TTD::Replay::ReplayEngine::GetRecordingType()const
			virtual RecordingType GetRecordingType() const;

			// [08]: public: virtual struct TTD::Replay::ThreadInfo const & TTD::Replay::ReplayEngine::GetThreadInfo(enum TTD::Replay::UniqueThreadId)const
			virtual ThreadInfo const& GetThreadInfo(UniqueThreadId) const;

			// [09]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetThreadCount()const
			virtual UINT64 GetThreadCount() const;

			// [10]: public: virtual struct TTD::Replay::ThreadInfo const * TTD::Replay::ReplayEngine::GetThreadList()const
			virtual ThreadInfo const* GetThreadList() const;

			// [11]: public: virtual unsigned __int64 const * TTD::Replay::ReplayEngine::GetThreadFirstPositionIndex()const
			virtual UINT64 const* GetThreadFirstPositionIndex() const;

			// [12]: public: virtual unsigned __int64 const * TTD::Replay::ReplayEngine::GetThreadLastPositionIndex()const
			virtual UINT64 const* GetThreadLastPositionIndex() const;

			// [13]: public: virtual unsigned __int64 const * TTD::Replay::ReplayEngine::GetThreadLifetimeFirstPositionIndex()const
			virtual UINT64 const* GetThreadLifetimeFirstPositionIndex() const;

			// [14]: public: virtual unsigned __int64 const * TTD::Replay::ReplayEngine::GetThreadLifetimeLastPositionIndex()const
			virtual UINT64 const* GetThreadLifetimeLastPositionIndex() const;

			// [15]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetThreadCreatedEventCount()const
			virtual UINT64 GetThreadCreatedEventCount() const;

			// [16]: public: virtual struct TTD::Replay::ThreadCreatedEvent const * TTD::Replay::ReplayEngine::GetThreadCreatedEventList()const
			virtual ThreadCreatedEvent const* GetThreadCreatedEventList() const;

			// [17]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetThreadTerminatedEventCount()const
			virtual UINT64 GetThreadTerminatedEventCount() const;

			// [18]: public: virtual struct TTD::Replay::ThreadTerminatedEvent const * TTD::Replay::ReplayEngine::GetThreadTerminatedEventList()const
			virtual ThreadTerminatedEvent const* GetThreadTerminatedEventList() const;

			// [19]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetModuleCount()const
			virtual UINT64 GetModuleCount() const;

			// [20]: public: virtual struct TTD::Replay::Module const * TTD::Replay::ReplayEngine::GetModuleList()const
			virtual Module const* GetModuleList() const;

			// [21]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetModuleInstanceCount()const
			virtual UINT64 GetModuleInstanceCount() const;

			// [22]: public: virtual struct TTD::Replay::ModuleInstance const * TTD::Replay::ReplayEngine::GetModuleInstanceList()const
			virtual ModuleInstance const* GetModuleInstanceList() const;

			// [23]: public: virtual unsigned __int64 const * TTD::Replay::ReplayEngine::GetModuleInstanceUnloadIndex()const
			virtual UINT64 const* GetModuleInstanceUnloadIndex() const;

			// [24]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetModuleLoadedEventCount()const
			virtual UINT64 GetModuleLoadedEventCount() const;

			// [25]: public: virtual struct TTD::Replay::ModuleLoadedEvent const * TTD::Replay::ReplayEngine::GetModuleLoadedEventList()const
			virtual ModuleLoadedEvent const* GetModuleLoadedEventList() const;

			// [26]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetModuleUnloadedEventCount()const
			virtual UINT64 GetModuleUnloadedEventCount() const;

			// [27]: public: virtual struct TTD::Replay::ModuleUnloadedEvent const * TTD::Replay::ReplayEngine::GetModuleUnloadedEventList()const
			virtual ModuleUnloadedEvent const* GetModuleUnloadedEventList() const;

			// [28]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetExceptionEventCount()const
			virtual UINT64 GetExceptionEventCount() const;

			// [29]: public: virtual struct TTD::Replay::ExceptionEvent const * TTD::Replay::ReplayEngine::GetExceptionEventList()const
			virtual ExceptionEvent const* GetExceptionEventList() const;

			// [30]: public: virtual struct TTD::Replay::ExceptionEvent const * TTD::Replay::ReplayEngine::GetExceptionAtOrAfterPosition(struct TTD::Replay::Position const &)const
			virtual ExceptionEvent const* GetExceptionAtOrAfterPosition(Position const&) const;

			// [31]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetKeyframeCount()const
			virtual UINT64 GetKeyframeCount() const;

			// [32]: public: virtual struct TTD::Replay::Position const * TTD::Replay::ReplayEngine::GetKeyframeList()const
			virtual Position const* GetKeyframeList() const;

			// [33]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetRecordClientCount()const
			virtual UINT64 GetRecordClientCount() const;

			// [34]: public: virtual struct TTD::Replay::RecordClient const * TTD::Replay::ReplayEngine::GetRecordClientList()const
			PLACE_HOLDER(GetRecordClientList);

			// [35]: public: virtual struct TTD::Replay::RecordClient const & TTD::Replay::ReplayEngine::GetRecordClient(enum TTD::RecordClientId)const
			PLACE_HOLDER(GetRecordClient);

			// [36]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetCustomEventCount()const
			virtual UINT64 GetCustomEventCount() const;

			// [37]: public: virtual struct TTD::Replay::CustomEvent const * TTD::Replay::ReplayEngine::GetCustomEventList()const
			PLACE_HOLDER(GetCustomEventList);

			// [38]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetActivityCount()const
			virtual UINT64 GetActivityCount() const;

			// [39]: public: virtual struct TTD::Replay::Activity const * TTD::Replay::ReplayEngine::GetActivityList()const
			PLACE_HOLDER(GetActivityList);

			// [40]: public: virtual unsigned __int64 TTD::Replay::ReplayEngine::GetIslandCount()const
			virtual UINT64 GetIslandCount() const;

			// [41]: public: virtual struct TTD::Replay::Island const * TTD::Replay::ReplayEngine::GetIslandList()const
			PLACE_HOLDER(GetIslandList);

			// [42]: public: virtual class TTD::Replay::ICursor * TTD::Replay::ReplayEngine::NewCursor(struct _GUID const &)
			virtual Cursor *NewCursor(GUID const&);

			// [43]: public: virtual enum TTD::Replay::IndexStatus TTD::Replay::ReplayEngine::BuildIndex(void (*)(void const *,struct TTD::Replay::IndexBuildProgressType const *), void const *, enum TTD::Replay::IndexBuildFlags)
			PLACE_HOLDER(BuildIndex);

			// [44]: public: virtual enum TTD::Replay::IndexStatus TTD::Replay::ReplayEngine::GetIndexStatus()const
			virtual IndexStatus GetIndexStatus() const;

			// [45]: public: virtual struct TTD::Replay::IndexFileStats TTD::Replay::ReplayEngine::GetIndexFileStats()const
			PLACE_HOLDER(GetIndexFileStats);

			// [46]: public: virtual void TTD::Replay::ReplayEngine::RegisterDebugModeAndLogging(enum TTD::Replay::DebugModeType,class TTD::ErrorReporting *)
			virtual void RegisterDebugModeAndLogging(TTD::Replay::DebugModeType, class TTD::ErrorReporting*);

			// [47]: public: virtual class TTD::Replay::IEngineInternals const * TTD::Replay::ReplayEngine::GetInternals()const
			PLACE_HOLDER(GetInternals);

			// [48]: public: virtual class TTD::Replay::IEngineInternals const * TTD::Replay::ReplayEngine::GetInternals()const
			PLACE_HOLDER(GetInternals_duplicate);

			// [49]: public: virtual void * TTD::Replay::ReplayEngine::`vector deleting destructor'(unsigned int)
			PLACE_HOLDER(vector_deleting_destructor);

			// [50]: public: virtual void TTD::Replay::ReplayEngine::Destroy()
			virtual void Destroy();

			// [51]: public: virtual bool TTD::Replay::ReplayEngine::Initialize(wchar_t const *)
			virtual bool Initialize(wchar_t const*);
		};
		static_assert(sizeof(ReplayEngine) == sizeof(ULONG_PTR), "Should be equal the size of a VFTABLE!");


		// ----------------------------------------------------------------------------------------------

		// TODO: Put the class defined types under the same namespace?

		// struct TTD::Replay::MemoryRange
		struct MemoryRange
		{
			Nirvana::GuestAddress addr;	// Base of virtual memory block
			LPCVOID buffer;	// Internal buffer for memory
			UINT64 mrSize;	// Always 32 but 64bit host. Size of this structure?
			UINT64 flags;	// 0xF if 32bit, 0xE if 64bit
		};

		// struct TTD::Replay::MemoryBuffer
		struct MemoryBuffer
		{
			Nirvana::GuestAddress addr;
			PVOID data;
			UINT64 size;
		};

		const enum BP_FLAGS
		{
			WRITE = 2,
			READ = 3,
			EXEC = 4
		};

		// struct TTD::Replay::MemoryWatchpointData
		struct MemoryWatchpointData
		{
			Nirvana::GuestAddress addr;
			UINT64 size;
			UINT64 flags;
		};
		typedef MemoryWatchpointData MemoryWatchpointResult;  // struct TTD::Replay::ICursorView::MemoryWatchpointResult

		// struct TTD::Replay::ActiveThreadInfo
		struct ActiveThreadInfo
		{
			ThreadInfo *info;
			Position next;  // Next position where thread is active
			Position last;  // Last position where this thread was active
		};

		// union TTD::Replay::RegisterContext
		struct RegisterContext
		{
			union
			{
				CONTEXT x64;  // For x86, registers are extended to 64bit values
				//ARM64EC_NT_CONTEXT a64;
				BYTE buffer[0xA70]; // Size from code
			};
		};

		// union TTD::Replay::ExtendedRegisterContext
		struct ExtendedRegisterContext
		{
			// TODO:Like struct CONTEXT but with MSRs or?
			BYTE buffer[0x2280]; // Size from code
		};

		// enum TTD::Replay::QueryMemoryPolicy
		enum QueryMemoryPolicy
		{
			MemoryPolicyOne = 1, // ??
			MemoryPolicyTwo = 2, // ?
			MemoryPolicyThree = 3, // ?
			DefaultMemoryPolicy = 4, // Returned by GetDefaultMemoryPolicy() on trace load.
		};

		typedef UINT32 ThreadId;			// TTD::ThreadId
		typedef UINT32 EventMask;			// TTD::Replay::EventMask
		typedef UINT32 GapKindMask;			// TTD::Replay::GapKindMask
		typedef UINT32 GapEventMask;		// TTD::Replay::GapEventMask
		typedef UINT32 ExceptionMask;		// TTD::Replay::ExceptionMask
		typedef UINT32 ReplayFlags;			// TTD::Replay::ReplayFlags

		class ExecutionState;
		// class ExecutionState is referenced as "IThreadView"
		typedef ExecutionState IThreadView;


		// Note: All code in these callbacks must be thread safe. They are called from a thread pool.

		// SetCallReturnCallback callback: Will get invoked for every CALL instruction during playback
		typedef void (WINAPI* const CallReturnCallback)(UINT64 lparm, Nirvana::GuestAddress addr_func, Nirvana::GuestAddress addr_ret, ExecutionState const *threadView);

		// SetIndirectJumpCallback callback: Will get invoked for every indirect JMP instruction during playback
		typedef void (WINAPI* const IndirectJumpCallback)(UINT64 lparm, Nirvana::GuestAddress addr_jmp, ExecutionState const *threadView);

		// SetMemoryWatchpointCallback callback: Will get invoked on every time a memory watch point is hit during playback.
		// A memory break point for data accesses and/or code execution.
		// Return TRUE to stop execution, FALSE to continue
		typedef bool (WINAPI* const MemoryWatchpointCallback)(UINT64 lparm, MemoryWatchpointResult const &result, IThreadView const *threadView);


		// const TTD::Replay::Cursor::`vftable'{for `TTD::Replay::ICursor'}
		// Referenced some times as "ICursor" in other classes
		class Cursor
		{
		public:
			// Output from ReplayForward() and ReplayBackward()
			struct ReplayResult
			{
				UINT64 unk00;     // 00 Unknown stack pointer
				UINT64 StepCount; // 08 Steps taken
				UINT64 unk10;	  // 10 Usually zero
				UINT64 unk18;	  // 18 ""
				UINT64 unk20;	  // 20	""
				UINT64 unk28;	  // 28 "" BYTE access
			};

			static const GUID IID_ICursorView;

		public:
			// [00]: public: virtual struct TTD::Replay::MemoryRange TTD::Replay::Cursor::QueryMemoryRange(enum Nirvana::GuestAddress,enum TTD::Replay::QueryMemoryPolicy)const
			virtual MemoryRange QueryMemoryRange(Nirvana::GuestAddress, QueryMemoryPolicy) const;

			// [01]: public: virtual struct TTD::Replay::MemoryBuffer TTD::Replay::Cursor::QueryMemoryBuffer(enum Nirvana::GuestAddress,struct TTD::TBufferView<0>,enum TTD::Replay::QueryMemoryPolicy)const
			virtual MemoryBuffer QueryMemoryBuffer(Nirvana::GuestAddress, __out TBufferView *BufferView, QueryMemoryPolicy) const;

			// [02]: public: virtual struct TTD::Replay::MemoryBufferWithRanges TTD::Replay::Cursor::QueryMemoryBufferWithRanges(enum Nirvana::GuestAddress,struct TTD::TBufferView<0>,unsigned __int64,struct TTD::Replay::MemoryRange *,enum TTD::Replay::QueryMemoryPolicy)const
			PLACE_HOLDER(QueryMemoryBufferWithRanges);

			// [03]: public: virtual void TTD::Replay::Cursor::SetDefaultMemoryPolicy(enum TTD::Replay::QueryMemoryPolicy)
			virtual void SetDefaultMemoryPolicy(QueryMemoryPolicy);

			// [04]: public: virtual enum TTD::Replay::QueryMemoryPolicy TTD::Replay::Cursor::GetDefaultMemoryPolicy()const
			virtual QueryMemoryPolicy GetDefaultMemoryPolicy() const;

			// [05]: public: virtual void * TTD::Replay::Cursor::UnsafeGetReplayEngine(struct _GUID const &)const
			PLACE_HOLDER(UnsafeGetReplayEngine);

			// [06]: public: virtual void const * TTD::Replay::Cursor::UnsafeAsInterface(struct _GUID const &)const
			PLACE_HOLDER(UnsafeAsInterface_const);

			// [07]: public: virtual void * TTD::Replay::Cursor::UnsafeAsInterface(struct _GUID const &)
			PLACE_HOLDER(UnsafeAsInterface);

			// [08]: public: virtual struct TTD::Replay::ThreadInfo const & TTD::Replay::Cursor::GetThreadInfo(enum TTD::ThreadId)const
			virtual ThreadInfo const& GetThreadInfo(ThreadId) const;

			// [09]: public: virtual enum Nirvana::GuestAddress TTD::Replay::Cursor::GetTebAddress(enum TTD::ThreadId)const
			virtual Nirvana::GuestAddress GetTebAddress(ThreadId) const;

			// [10]: public: virtual struct TTD::Replay::Position const & TTD::Replay::Cursor::GetPosition(enum TTD::ThreadId)const
			virtual Position const& GetPosition(ThreadId) const;

			// [11]: public: virtual struct TTD::Replay::Position const & TTD::Replay::Cursor::GetPreviousPosition(enum TTD::ThreadId)const
			virtual Position const& GetPreviousPosition(ThreadId) const;

			// [12]: public: virtual enum Nirvana::GuestAddress TTD::Replay::Cursor::GetProgramCounter(enum TTD::ThreadId)const
			virtual Nirvana::GuestAddress GetProgramCounter(ThreadId) const;

			// [13]: public: virtual enum Nirvana::GuestAddress TTD::Replay::Cursor::GetStackPointer(enum TTD::ThreadId)const
			virtual Nirvana::GuestAddress GetStackPointer(ThreadId) const;

			// [14]: public: virtual enum Nirvana::GuestAddress TTD::Replay::Cursor::GetFramePointer(enum TTD::ThreadId)const
			virtual Nirvana::GuestAddress GetFramePointer(ThreadId) const;

			// [15]: public: virtual unsigned __int64 TTD::Replay::Cursor::GetBasicReturnValue(enum TTD::ThreadId)const
			virtual UINT64 GetBasicReturnValue(ThreadId) const;

			// [16]: public: virtual union TTD::Replay::RegisterContext TTD::Replay::Cursor::GetCrossPlatformContext(enum TTD::ThreadId)const
			virtual RegisterContext GetCrossPlatformContext(ThreadId) const;

			// [17]: public: virtual union TTD::Replay::ExtendedRegisterContext TTD::Replay::Cursor::GetAvxExtendedContext(enum TTD::ThreadId)const
			virtual ExtendedRegisterContext GetAvxExtendedContext(ThreadId) const;

			// [18]: public: virtual unsigned __int64 TTD::Replay::Cursor::GetModuleCount()const
			virtual UINT64 GetModuleCount() const;

			// [19]: public: virtual struct TTD::Replay::ModuleInstance const * TTD::Replay::Cursor::GetModuleList()const
			virtual ModuleInstance const* GetModuleList() const;

			// [20]: public: virtual unsigned __int64 TTD::Replay::Cursor::GetThreadCount()const
			virtual UINT64 GetThreadCount() const;

			// [21]: public: virtual struct TTD::Replay::ActiveThreadInfo const * TTD::Replay::Cursor::GetThreadList()const
			virtual ActiveThreadInfo const* GetThreadList() const;

			// [22]: public: virtual void TTD::Replay::Cursor::SetEventMask(enum TTD::Replay::EventMask)
			virtual void SetEventMask(EventMask);

			// [23]: public: virtual enum TTD::Replay::EventMask TTD::Replay::Cursor::GetEventMask()const
			virtual EventMask GetEventMask() const;

			// [24]: public: virtual void TTD::Replay::Cursor::SetGapKindMask(enum TTD::Replay::GapKindMask)
			virtual void SetGapKindMask(GapKindMask);

			// [25]: public: virtual enum TTD::Replay::GapKindMask TTD::Replay::Cursor::GetGapKindMask()const
			virtual GapKindMask GetGapKindMask() const;

			// [26]: public: virtual void TTD::Replay::Cursor::SetGapEventMask(enum TTD::Replay::GapEventMask)
			virtual void SetGapEventMask(GapEventMask);

			// [27]: public: virtual enum TTD::Replay::GapEventMask TTD::Replay::Cursor::GetGapEventMask()const
			virtual GapEventMask GetGapEventMask() const;

			// [28]: public: virtual void TTD::Replay::Cursor::SetExceptionMask(enum TTD::Replay::ExceptionMask)
			virtual void SetExceptionMask(ExceptionMask);

			// [29]: public: virtual enum TTD::Replay::ExceptionMask TTD::Replay::Cursor::GetExceptionMask()const
			virtual ExceptionMask GetExceptionMask() const;

			// [30]: public: virtual void TTD::Replay::Cursor::SetReplayFlags(enum TTD::Replay::ReplayFlags)
			virtual void SetReplayFlags(ReplayFlags);

			// [31]: public: virtual enum TTD::Replay::ReplayFlags TTD::Replay::Cursor::GetReplayFlags()const
			virtual ReplayFlags GetReplayFlags() const;

			// [32]: public: virtual bool TTD::Replay::Cursor::AddMemoryWatchpoint(struct TTD::Replay::MemoryWatchpointData const &)
			virtual bool AddMemoryWatchpoint(MemoryWatchpointData const&);

			// [33]: public: virtual bool TTD::Replay::Cursor::RemoveMemoryWatchpoint(struct TTD::Replay::MemoryWatchpointData const &)
			virtual bool RemoveMemoryWatchpoint(MemoryWatchpointData const&);

			// [34]: public: virtual bool TTD::Replay::Cursor::AddPositionWatchpoint(struct TTD::Replay::PositionWatchpointData const &)
			PLACE_HOLDER(AddPositionWatchpoint);

			// [35]: public: virtual bool TTD::Replay::Cursor::RemovePositionWatchpoint(struct TTD::Replay::PositionWatchpointData const &)
			PLACE_HOLDER(AddPosRemovePositionWatchpointtionWatchpoint);

			// [36]: public: virtual void TTD::Replay::Cursor::Clear()
			virtual void Clear();

			// [37]: public: virtual void TTD::Replay::Cursor::SetPosition(struct TTD::Replay::Position const &)
			virtual void SetPosition(Position const&);

			// [38]: public: virtual void TTD::Replay::Cursor::SetPositionOnThread(enum TTD::Replay::UniqueThreadId,struct TTD::Replay::Position const &)
			virtual void SetPositionOnThread(UniqueThreadId, Position const&);

			// [39]: public: virtual void TTD::Replay::Cursor::SetMemoryWatchpointCallback(bool (*const)(unsigned __int64,struct TTD::Replay::ICursorView::MemoryWatchpointResult const &,class TTD::Replay::IThreadView const *),unsigned __int64)
			virtual void SetMemoryWatchpointCallback(bool (* const)(UINT64, MemoryWatchpointResult const&, IThreadView const*), UINT64 addr_ret);

			// [40]: public: virtual void TTD::Replay::Cursor::SetPositionWatchpointCallback(bool (*const)(unsigned __int64,struct TTD::Replay::Position const &,class TTD::Replay::IThreadView const *),unsigned __int64)
			virtual void SetPositionWatchpointCallback(bool (* const)(UINT64, Position const&, IThreadView const*), UINT64 addr_ret);

			// [41]: public: virtual void TTD::Replay::Cursor::SetGapEventCallback(bool (*const)(unsigned __int64,enum TTD::Replay::GapKind,enum TTD::Replay::GapEventType,class TTD::Replay::IThreadView const *),unsigned __int64)
			PLACE_HOLDER(SetGapEventCallback);

			// [42]: public: virtual void TTD::Replay::Cursor::SetThreadContinuityBreakCallback(void (*const)(unsigned __int64),unsigned __int64)
			virtual void SetThreadContinuityBreakCallback(void (* const)(UINT64), UINT64 lparm);

			// [43]: public: virtual void TTD::Replay::Cursor::SetReplayProgressCallback(void (*const)(unsigned __int64,struct TTD::Replay::Position const &),unsigned __int64)
			virtual void SetReplayProgressCallback(void (* const)(UINT64, Position const&), UINT64 lparm);

			// [44]: public: virtual void TTD::Replay::Cursor::SetFallbackCallback(void (*const)(unsigned __int64,bool,enum Nirvana::GuestAddress,unsigned __int64,class TTD::Replay::IThreadView const *),unsigned __int64)
			virtual void SetFallbackCallback(void (* const)(UINT64, bool, Nirvana::GuestAddress, UINT64, IThreadView const*), UINT64 lparm);

			// [45]: public: virtual void TTD::Replay::Cursor::SetCallReturnCallback(void (*const)(unsigned __int64,enum Nirvana::GuestAddress,enum Nirvana::GuestAddress,class TTD::Replay::IThreadView const *),unsigned __int64)
			virtual void SetCallReturnCallback(void (* const)(UINT64 lparm, Nirvana::GuestAddress addr_func, Nirvana::GuestAddress addr_ret, IThreadView const*), UINT64 lparm);

			// [46]: public: virtual void TTD::Replay::Cursor::SetIndirectJumpCallback(void (*const)(unsigned __int64,enum Nirvana::GuestAddress,class TTD::Replay::IThreadView const *),unsigned __int64)
			virtual void SetIndirectJumpCallback(void (* const)(UINT64 lparm, Nirvana::GuestAddress, IThreadView const*), UINT64 lparm);

			// [47]: public: virtual void TTD::Replay::Cursor::SetRegisterChangedCallback(void (*const)(unsigned __int64,unsigned char,void const *,void const *,unsigned __int64,class TTD::Replay::IThreadView const *),unsigned __int64)
			virtual void SetRegisterChangedCallback(void (* const)(UINT64, unsigned char, void const*, void const*, UINT64, IThreadView const*), UINT64 lparm);

			// [48]: public: virtual struct TTD::Replay::ICursorView::ReplayResult TTD::Replay::Cursor::ReplayForward(struct TTD::Replay::Position,enum TTD::Replay::StepCount)
			virtual ReplayResult ReplayForward(Position, UINT64 StepCount);

			// [49]: public: virtual struct TTD::Replay::ICursorView::ReplayResult TTD::Replay::Cursor::ReplayBackward(struct TTD::Replay::Position,enum TTD::Replay::StepCount)
			virtual ReplayResult ReplayBackward(Position, UINT64 StepCount);

			// [50]: public: virtual void TTD::Replay::Cursor::InterruptReplay()
			virtual void InterruptReplay();

			// [51]: public: virtual class TTD::Replay::IEngineInternals const * TTD::Replay::ReplayEngine::GetInternals()const
			PLACE_HOLDER(GetInternals);

			// [52]: public: virtual class TTD::Replay::IEngineInternals const * TTD::Replay::ReplayEngine::GetInternals()const
			PLACE_HOLDER(GetInternals_duplicate);

			// [53]: public: virtual unsigned __int64 TTD::Replay::Cursor::GetInternalData(enum TTD::Replay::ICursorView::InternalDataId,void *,unsigned __int64)const
			PLACE_HOLDER(GetInternalData);

			// [54]: public: virtual void * TTD::Replay::Cursor::`vector deleting destructor'(unsigned int)
			PLACE_HOLDER(vector_deleting_destructor);

			// [55]: public: virtual void TTD::Replay::Cursor::Destroy()
			virtual void Destroy();
		};
		static_assert(sizeof(Cursor) == sizeof(ULONG_PTR), "Should be equal the size of just a VFTABLE!");


		// ----------------------------------------------------------------------------------------------

		// const TTD::Replay::ExecutionState::`vftable'{for `TTD::Replay::IThreadView'}
		// Referenced as "IThreadView" from other classes
		class ExecutionState
		{
		public:
			// [00]: public: virtual struct TTD::Replay::ThreadInfo const & TTD::Replay::ExecutionState::GetThreadInfo()const
			virtual ThreadInfo const& GetThreadInfo() const;

			// [01]: public: virtual enum Nirvana::GuestAddress TTD::Replay::ExecutionState::GetTebAddress()const
			virtual Nirvana::GuestAddress GetTebAddress() const;

			// [02]: public: virtual struct TTD::Replay::Position const & TTD::Replay::ExecutionState::GetPosition()const
			virtual Position const& GetPosition() const;

			// [03]: public: virtual struct TTD::Replay::Position TTD::Replay::ExecutionState::GetPreviousPosition()const
			virtual Position GetPreviousPosition() const;

			// [04]: public: virtual enum Nirvana::GuestAddress TTD::Replay::ExecutionState::GetProgramCounter()const
			virtual Nirvana::GuestAddress GetProgramCounter() const;

			// [05]: public: virtual enum Nirvana::GuestAddress TTD::Replay::ExecutionState::GetStackPointer()const
			virtual Nirvana::GuestAddress GetStackPointer() const;

			// [06]: public: virtual enum Nirvana::GuestAddress TTD::Replay::ExecutionState::GetFramePointer()const
			virtual Nirvana::GuestAddress GetFramePointer() const;

			// [07]: public: virtual unsigned __int64 TTD::Replay::ExecutionState::GetBasicReturnValue()const
			virtual UINT64 GetBasicReturnValue() const;

			// [08]: public: virtual union TTD::Replay::RegisterContext TTD::Replay::ExecutionState::GetCrossPlatformContext()const
			virtual RegisterContext GetCrossPlatformContext() const;

			// [09]: public: virtual union TTD::Replay::ExtendedRegisterContext TTD::Replay::ExecutionState::GetAvxExtendedContext()const
			virtual ExtendedRegisterContext GetAvxExtendedContext() const;

			// [10]: public: virtual struct TTD::Replay::MemoryRange TTD::Replay::ExecutionState::QueryMemoryRange(enum Nirvana::GuestAddress)const
			PLACE_HOLDER(QueryMemoryRange);

			// [11]: public: virtual struct TTD::Replay::MemoryBuffer TTD::Replay::ExecutionState::QueryMemoryBuffer(enum Nirvana::GuestAddress,struct TTD::TBufferView<0>)const
			virtual MemoryBuffer QueryMemoryBuffer(Nirvana::GuestAddress, __out TBufferView *TBufferView) const;

			// [12]: public: virtual struct TTD::Replay::MemoryBufferWithRanges TTD::Replay::ExecutionState::QueryMemoryBufferWithRanges(enum Nirvana::GuestAddress,struct TTD::TBufferView<0>,unsigned __int64,struct TTD::Replay::MemoryRange *)const
			PLACE_HOLDER(QueryMemoryBufferWithRanges);

			// [13]: public: virtual void * TTD::Replay::ExecutionState::`scalar deleting destructor'(unsigned int)
			PLACE_HOLDER(scalar_deleting_destructor);
		};
		static_assert(sizeof(IThreadView) == sizeof(ULONG_PTR), "Should be equal the size of just a VFTABLE!");

	} //namespace Replay

	// struct TTD::SystemInfo
	struct SystemInfo
	{
		UINT32 unk00;	// 000 1
		UINT32 unk04;	// 004 10 windows version?
		UINT32 unk08;	// 008 0
		UINT32 unk0C;	// 00C 32bit 0x4e84, 64bit 0x5378
		UINT64 unk10;   // 010 Large address
		UINT64 unk18;   // 018 Large address
		UINT32 unk20;	// 020 0x2625A "Zb.."
		BYTE unk24[22];	// 024 Usually all zeros

		WORD wProcessorLevel; // 03A 6
		WORD wProcessorRevision; // 03C 0x9702

		WORD unk3E;		// 03E 0x0118 Byte core count and byte cpu count?
		UINT32 unk40;	// 040 6
		UINT32 unk44;	// 044 2
		UINT32 unk48;	// 048 0x23F0
		UINT32 unk4C;	// 04C 2
		UINT32 unk50;	// 050 0
		UINT32 unk54;	// 054 0x100 from cpuid 0x80000007?

		char ManufacturerID[12]; // 58 32bit, "GenuineIntel", etc., on 64bit garbage chars

		UINT32 unk64;	// 064 32bit 0x7FFAFBFF, 64bit 0
		UINT32 unk68;	// 068 32bit 0xBFEBFBFF, 64bit 0
		UINT32 unk6C;	// 06C 0

		WCHAR User[64];	// 070 User name
		WCHAR Machine[64]; // 0F0 Machine name

		UINT32 unk170;	// 170 10
		UINT32 unk174;	// 174 1
		UINT32 unk178;	// 178 4
		UINT32 unk17C;	// 17C 32bit 1, 64bit 0
		UINT64 unk180;	// 180 0
		UINT64 unk188;  // 188 "TTDReplay.dll" vftable
		UINT64 unk190;  // 190 "TTDReplay.dll" Simple callback clears pointer at offset [0], [8], and [0x10]
		BYTE unk198[40]; // 198 Usually all zeros
		UINT64 unk1C0;  // 1C0 Class pointer with "TTDReplay.dll" vftable
	};  // Size 1C8

	HRESULT CreateReplayEngine(__in LPCWSTR TtdPath, __out TTD::Replay::ReplayEngine **pReplayEngine);

} // namespace TTD

#undef PLACE_HOLDER
