
// Plugin main
#include "StdAfx.h"

#define SETTINGS_FILE "MissingLink.ini"

#define OPTION_USE_TAG (1 << 0)
#define OPTION_JSON_DB (1 << 1)

// MissingLink.cpp
extern BOOL ProcessTraceFile(LPCSTR tracefile, LPCSTR winDbgXPath, LPCSTR jsonDbPath, BOOL useTag);


static void idaapi OnRepoLink(int button_code, form_actions_t &fa) { open_url("https://github.com/kweatherman/ida_missinglink/"); }

static bool idaapi run(size_t arg)
{
	static const char mainDialog[] =
	{
		"BUTTON YES* Continue\n" // 'Continue' instead of 'okay'

		// Dialog title on bar
		"Missing Link\n\n"

		// Message text
		"Missing Link: Time Travel Debug (TTD) trace file - indirect branch info comment plugin.\n"
		"%q\n"
		"\t\xC2\xA9 2023 Kevin Weatherman\n"

		"<#Click to open IDA Missing Link repo page.#Missing Link Github:k::>\n\n"

		"<DbgX AMD64 TTD folder:F:0:62::>\n\n"

		"Options:\n"
		"<#Prefix indrect branch comments with 'ML' tags.#Place 'ML' comment tags.:C:36::>\n"
		"<#Save the module and indirect branch data into a JSON DB file.#Save JSON DB.:C:36::>>\n"
	};
	qstring version, tmp;

	try
	{
		// IDA must be IDLE
		if (!auto_is_ok())
		{
			msg("** Wait for IDA to finish processing before starting plugin! **\n** Aborted **\n\n");
			goto exit;
		}

		// Get .ini settings path based on our plugin  DLL path
		char settingsFilePath[QMAXPATH] = {};
		HMODULE myModule = NULL;
		GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR) run, &myModule);
		GetModuleFileNameA(myModule, settingsFilePath, QMAXPATH);
		LPSTR fileName = PathFindFileNameA(settingsFilePath);
		if (!fileName)
		{
			msg("** Failed to build the settings file path! **\n");
			goto exit;
		}
		*fileName = 0;
		strcat_s(settingsFilePath, QMAXPATH, SETTINGS_FILE);

		// Get saved WinDbgX path, or use a default
		char winDbgXPath[QMAXPATH] = {};
		GetPrivateProfileStringA("settings", "windbgx_path", "C:\\Program Files\\WindowsApps\\Microsoft.WinDbg_1.2210.3001.0_x64__8wekyb3d8bbwe\\amd64\\ttd", winDbgXPath, QMAXPATH, settingsFilePath);

		// Do main dialog
		version.sprnt("v%s, built %s.", GetVersionString(MY_VERSION, tmp).c_str(), __DATE__);
		msg("\n>> " MSG_TAG "%s\n", version.c_str());
		REFRESH();

		WORD optionFlags = OPTION_USE_TAG;
		//int result = ask_form(mainDialog, &version, OnRepoLink, traceFile, winDbgXPath, &optionFlags);
		int result = ask_form(mainDialog, &version, OnRepoLink, winDbgXPath, &optionFlags);
		if (!result)
		{
			msg(" - Canceled -\n\n");
			goto exit;
		}

		// Verify the WinDbgX folder exists
		if (!PathFileExistsA(winDbgXPath))
		{
			msg("** WinDbg preview (aka \"WinDbgX\" folder doesn't exist! **\nSet the path in the plug-in dialog first.\n** Aborted **\n\n");
			goto exit;
		}

		// Ask for trace file path
		LPSTR traceFileAsk = ask_file(FALSE, "*.run;*.zip;*.cab", "Missing Link: Select trace file");
		if(!traceFileAsk)
		{
			msg(" - Canceled -\n\n");
			goto exit;
		}
		char traceFile[MAX_PATH];
		strncpy_s(traceFile, MAX_PATH, traceFileAsk, MAX_PATH-1);

		// Get optional JSON DB save path
		LPSTR jsonFile = NULL;
		if (optionFlags & OPTION_JSON_DB)
		{
			jsonFile = ask_file(TRUE, "*.json", "Missing Link:: Select JSON DB save file");
			if (!jsonFile)
			{
				msg(" - Canceled -\n\n");
				goto exit;
			}
		}

		// Load and process trace file..
		TIMESTAMP startTime = GetTimestamp();
		if (ProcessTraceFile(traceFile, winDbgXPath, jsonFile, ((optionFlags & OPTION_USE_TAG) ? TRUE : FALSE)))
		{
			// On success, save the WinDbgX path for next time
			WritePrivateProfileStringA("settings", "windbgx_path", winDbgXPath, settingsFilePath);

			char buffer[64];
			msg("Done, total time: %s.\n", TimestampString((GetTimestamp() - startTime), buffer));
			refresh_idaview_anyway();
		}
		else
			msg("** Aborted **\n\n");
	}
	CATCH("run()");

	exit:;
    return true;
}

static plugmod_t* idaapi init()
{
	MH_Initialize();
    return PLUGIN_OK;
}

static void idaapi term()
{
	MH_Uninitialize();
}

__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC,
    init,
    term,
    run,
    "TTD trace file - indirect branch info comment plugin.",
    "Missing Link plugin",
    "Missing Link",
    ""
};
