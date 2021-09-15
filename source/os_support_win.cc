#include "os_support.h"


#if defined(_WIN32)
#include <windows.h>

bool is_acceptable_os_version(const std::string& osMinRequiredVersion)
{
	if (osMinRequiredVersion.empty())
	{
		return true;
	}

	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, { 0 }, 0, 0 };
	DWORDLONG const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			VerSetConditionMask(
				0, VER_MAJORVERSION, VER_GREATER_EQUAL),
			VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	sscanf_s(osMinRequiredVersion.c_str(), "%lu.%lu.%hu", &osvi.dwMajorVersion, &osvi.dwMinorVersion, &osvi.wServicePackMajor);
	return !VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask);
}

bool is_matched_os_name(const std::string& osName)
{
	if (_stricmp(osName.c_str(), "windows") == 0) return true;
#ifdef _WIN64
	if (_stricmp(osName.c_str(), "windows-x64") != 0) return true;
#else
	if (_stricmp(osName.c_str(), "windows-x86") != 0) return true;
#endif
	return false;
}

bool execute(const std::string& package, const std::string& args)
{
	SHELLEXECUTEINFOA sei = { 0 };
	sei.cbSize = sizeof(sei);
	sei.lpFile = package.c_str();
	sei.nShow = SW_SHOWDEFAULT;
	sei.fMask = SEE_MASK_FLAG_NO_UI;	// We display our own dialog box on error

	if (!args.empty())
	{
		sei.lpParameters = args.c_str();
	}

	return !!ShellExecuteExA(&sei);
}

#ifdef _USRDLL
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved)  // reserved
{
	// Perform actions based on the reason for calling.
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
#endif //_USRDLL

#endif
