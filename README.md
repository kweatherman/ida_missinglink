## Missing Link

[Time Travel Debug (TTD)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview) trace file - indirect branch info comment IDA Pro plugin.  
Takes a trace file of a Windows executable using Microsoft® TTD with *[WinDbgX](https://apps.microsoft.com/store/detail/windbg-preview/9PGJGD53TN86)* or using the *TTD.exe* utility and adds missing indirect branch target info in IDA Pro as assembly view comments.  
Main use case is for help in debugging and reversing Windows executables with heavy C++ abstractions or otherwise ones with many indirect branches (x86/AMD64 CALL and JMP by pointer instructions).

#### Example before
<img align="left" src="/images/before1.png">
<br><br><br><br><br><br>

#### After
<img align="left" src="/images/after1.png">
<br><br><br><br><br><br>

Now we see the `call edi` at 403C67h called into six local functions during the input trace.

Another example, we see this time an external call into `kernelbase.dll!InitializeCriticalSectionEx` was made:
<img align="left" src="/images/after2.png">
<br><br><br><br>

Might not seem that useful at first glance, but can be very helpful for executables that are C++ OOP paradigm heavy to see where the indirect branches go. Something you can't get from just static analysis alone. One would have to step through the instructions in a debugger and mark down the call targets manually.

Also by inference, one can get some sense of call coverage in function blocks where there are multiple indirect branches inside a function. If you see a block with `#ML:` comments, you know that block was executed. If there are other blocks with indirect branches and no comments then more than likely that block was not hit (but should verify in a WinDbgX TTD session with a BP on the block if its important). If there are no comments at all in a function with indirect branches, it was probably never executed at all.

### Installation

Copy `IDA_MissingLink.dll` and `IDA_MissingLink64.dll` to your IDA `plugins` directory.  
Add a hotkey for the plugin in your IDA "plugins.cfg" or invoke from IDA's Edit->Plugins menu.  
Requires IDA Pro version 8'ish.

### Using
Invoke the plugin via its hotkey or via the IDA Edit/Plugin menu:
<img align="left" src="/images/main.png">
<br><br><br><br><br><br><br><br><br><br><br><br><br><br>

**DbgX AMD64 TTD folder**:  First you need to set where your WinDbgX AMD64\TTD folder is located here. 
If you have the latest WinDbgX version (as of 2/23/2023) it will be the default:
`C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2210.3001.0_x64__8wekyb3d8bbwe\amd64\ttd` path.
To make the TTD folder more accessible since that app folder has limited rights, etc., copy the whole WinDbgX folder to something like `C:\Utility\WinDbgX`. And then you would input `C:\Utility\WinDbgX\amd64\ttd` in this box.

##### Options

* **Place 'ML' comment tags**: Check this (the default) to place a `#ML:` tag at each plugin placed plugin comment to help discern between manually placed and plugin placed comments.

* **Save JSON DB**:  Check to optionally save module list and collected indirect branch info to a JSON DB file.  
  This data can be useful for gathering stats like a list of modules and function addressed called within complex multi-module targets, etc.  
  See the repo included `ml_db_loader.py` loader module and JSON data dump example.

#### Operation

**Warning: The plugin will overwrite any existing comments on lines where indirect branches are found. Make a snapshot/backup of your IDB first.**

1. Click "Continue" to start. You will be presented with a file load dialog to select a trace ".run" (or trace file in a "zip" or "cab") file.

2. If you optionally checked "Save JSON DB" then you will be presented with a JSON save file dialog. Select a folder and a save file name.

3. Let the plugin run.

   Depending on the size of the trace file, size of the executable, etc., it could take anywhere from just seconds to serval minutes to complete.  
   Note: The MS trace replay engine will utilize multiple threads using the MS thread pool API internally. The higher the spec machine and physical core count, the faster the plugin will process the trace.

On completion, the log output should look something like this:
![example_output](/images/example_output.png)
...

First a dump of all the modules in the trace, followed by the list of indirect branch source addresses that you can click on.  
See the top for example of what the assembly view comments look like.

The module list shows original captured address bases.  
For best results, rebase your IDA DB to the base address as was recorded in your TTD trace first.

Can be applied to any module in the trace (with the exception of non-loaded ones, see "Known problems" below) not just the main executable.  
This works particularly well for processes made up of multiple modules vs one large PE file.

#### Comment format

The placed target comments are organized in such a way to convey the information in a readable terse way.

##### Comment format rules:  

1) Only short module names are displayed (not the full path). Can be confusing for rare cases where multiple of the same short named module exist in a trace.
2) For target addresses that are outside of a module space, they are displayed with their original trace relative address prefixed with a '*'.
3) Target addresses are sorted from left to right by occurrence count. The address with the most hits is shown first.
4) If the target DLL ends with a standard ".dll" extension, it's trimmed off the name to help reduce comment lengths.
5) If the the total characters exceeds the COMMENT_STRING_LIMIT constant limit, the end of the comment will be appended with a " ..." to indicate this out of space condition.

### Recording a TTD trace

The traditional way to record a TTD trace is to do it within WinDbgX. Directions how to do this are here: ["Time Travel Debugging - Record a trace"](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-record).  
But the TDD system itself is not actually a debugger (it's some sort of sophisticated instrumented tracing system) and can be controlled from the command line.

All paths here are relative to:   
`C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2210.3001.0_x64__8wekyb3d8bbwe\amd64\ttd`  
or where ever you have WinDbgX plus "amd64\ttd".

##### Trace a running process

1) Start the process and get it's PID.
   Get the PID from the command line using one of these options ["Get process id with Windows Cmd"](https://superuser.com/questions/1705884/get-process-id-with-windows-cmd), or from a GUI using [ProcessExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer), or [ProcessHacker](https://processhacker.sourceforge.io/), etc.
2) Run the command line: `ttd.exe -out "C:\MyTraces" -attach <PID>` to start the trace. Where "C:\MyTraces" is trace file output folder.
3) Now exercise various functions and actions in the target process of interest for which you whish to get good code trace coverage.

When done with the tracing, either do a command line `ttd.exe -stop <PID>` to stop, or just terminate the process.

##### Start trace on process creation

Using the [Image File Execution Options (IFEO)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/xperf/image-file-execution-options) "Debugger attach" feature, we can setup "TTD.exe" to start tracing on the target by file name as soon as the executable starts so one can capture all of the process initialization code from the beginning.

A handy command line way to set the registry entry is:  
`reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MyTarget.exe" /v Debugger /t REG_SZ /d "C:\MyWindDbgX\amd64\ttd\ttd.exe -Out "C:\MyTraces"" /f`  
Where "C:\MyWindDbgX" is your WinDbgX folder (shortened here for brevity), and "MyTarget.exe" is the short file name for the target executable.

To stop the trace, can use the same `ttd.exe -out "C:\MyTraces" -attach <PID>` mentioned above, or just terminate the recording process to end it.

To remove the automatic tracing registry entry use the command line:  
`reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MyTarget.exe" /f`

Trace file names are serialized. On your first recording it will be "MyTarget01.run", the next one "MyTarget02.run", and so on.

### Motivation

I originally thought up this tool idea after spending countless hours reversing and debugging large multiple module composed executables built with heavy C++ class paradigms. Repeated thoughts of: "Wouldn't it be nice to know where these pointer calls and jumps go?". 

Plus some of my colleagues raved about how TTD (using [WinDbgX aka "WinDbg Preview"](https://apps.microsoft.com/store/detail/windbg-preview/9PGJGD53TN86)) greatly improved debugging Windows applications.

Then seeing the excellent [ttd-bindings](https://github.com/commial/ttd-bindings) project by commial/Ajax, and seeing the derivative [*ttddbg - Time Travel Debugging IDA plugin*](https://github.com/airbus-cert/ttddbg), it was time to do some R&D and build this tool up.

### DbgTtd vs ttd-bindings

Differences between my "Time Travel Debugger engine interface" (DbgTtd) used here, and commial's ttd-bindings (TTDB)  from which DbgTtd is derived.

* Preference for derived C++ namespaces vs using Snake_Case/Title_Case. I.E. With DbgTtd it's "TTD::Replay::ReplayEngine" vs the "TTD_Replay_ReplayEngine" TTDB style.
* By declaring all derived member functions as *virtual*, there is no need for wrapper functions that TTDB uses and makes the code easier to read in the process. The code will generate a single *vftable* offset internally as expected.
* Additional things defined (to at least some extent) like *TTD::Replay::RegisterContext*, *TTD::Replay::QueryMemoryPolicy*, *TTD::SystemInfo*, and many additional class members.
* General cleanup and reduction in code bulk preferring Windows APIs like Wincrypt over external 3rd party code et al. 
* Using exception handling to catch potential crashes within the engine.
* Added an *ErrorReporting* setup which handles internal errors to avoid common logical crashes (see [TTDB #22](https://github.com/commial/ttd-bindings/issues/22)).

Hopefully MS will release an official API so these  interoperability layers will no longer be needed.

### Known problems

* For what ever reason, the MS TDD recording engine doesn't always save a complete DLL image in memory (think Windows Minidump *.dmp* files which are similar). Almost always this will be `kernel32.dll` that is missing. Not sure what the reason is, hopefully MS will fix it in the next TTD release.
* Occasionally DLL load and unload events are missing from traces. The plugin does it's best to try to sort this situation out when DLLs overlap into the same memory space (from temporal DLL unload and load operations). An issue within the MS tracer engine apparently.
* The "Cancel" button on my *WaitBoxEx* custom wait box doesn't actually cancel anything. There are problems yet to be solved for it to function properly.

### Building

Built using Visual Studio 2022, on Windows 10 64bit, with the only external dependency being the official IDA Pro C/C++ SDK.  
The setup in the project file looks for an environment variable `_IDADIR` from which it expects to find the "idasdk/include" and "idasdk/lib" folders from there where the IDA SDK is located (not using `IDADIR` since IDA uses it and it can cause conflicts if you have more than one installed IDA version).

Python 3.10'ish or better to use the `ml_db_loader.py` JSON DB module/loader script.

### Credits

Microsoft® for the Windows [TTD](https://github.com/commial/ttd-bindings/issues/22) technology et al.  
Thanks to commial/Ajax for [ttd-bindings](https://github.com/commial/ttd-bindings) that made this project possible.

### License

Released under MIT © 2023 By Kevin Weatherman  
JSON for Modern C++, Copyright &copy; 2013-2023 [Niels Lohmann], MIT license  
Hacker Disassembler Engine 64, Copyright © 2009, Vyacheslav Patkov.