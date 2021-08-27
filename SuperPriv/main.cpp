/**
* from admin to TrustedInstaller, 
* 这里的权限继承自 TrustedInstaller.exe, 同时是system
*/

#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#include <iostream>
#include <string>
#include <codecvt>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

void EnablePrivilegeWithToken(HANDLE &hToken, wstring privilegeName)
{
	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid))
	{
		string errstr="LookupPrivilegeValue failed: " + to_string(GetLastError());
		printf("%s, %ls\n", errstr.c_str(), privilegeName.c_str());
		return;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		throw runtime_error("AdjustTokenPrivilege failed: " + to_string(GetLastError()));
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

void EnablePrivilege(wstring privilegeName)
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		throw runtime_error("OpenProcessToken failed: " + to_string(GetLastError()));

	EnablePrivilegeWithToken(hToken, privilegeName);
	CloseHandle(hToken);
}

DWORD GetProcessIdByName(wstring processName)
{
	HANDLE hSnapshot;
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
	{
		throw runtime_error("CreateToolhelp32Snapshot failed: " + to_string(GetLastError()));
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
		throw runtime_error("Process32First failed: " + to_string(GetLastError()));
	}

	if (pid == -1)
	{
		CloseHandle(hSnapshot);
		throw runtime_error("process not found: " + wstring_convert<codecvt_utf8<wchar_t>>().to_bytes(processName));
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
		throw runtime_error("OpenProcess failed (winlogon.exe): " + to_string(GetLastError()));
	}

	HANDLE hSystemToken;
	if (!OpenProcessToken(
		hSystemProcess,
		MAXIMUM_ALLOWED,
		&hSystemToken))
	{
		CloseHandle(hSystemProcess);
		throw runtime_error("OpenProcessToken failed (winlogon.exe): " + to_string(GetLastError()));
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
		throw runtime_error("DuplicateTokenEx failed (winlogon.exe): " + to_string(GetLastError()));
	}

	if (!ImpersonateLoggedOnUser(hDupToken))
	{
		CloseHandle(hDupToken);
		CloseHandle(hSystemToken);
		throw runtime_error("ImpersonateLoggedOnUser failed: " + to_string(GetLastError()));
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
		throw runtime_error("OpenSCManager failed: " + to_string(GetLastError()));
	}

	SC_HANDLE hService;
	if ((hService = OpenServiceW(
		hSCManager,
		L"TrustedInstaller",
		GENERIC_READ | GENERIC_EXECUTE)) == nullptr)
	{
		CloseServiceHandle(hSCManager);
		throw runtime_error("OpenService failed: " + to_string(GetLastError()));
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
				throw runtime_error("StartService failed: " + to_string(GetLastError()));
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
	throw runtime_error("QueryServiceStatusEx failed: " + to_string(GetLastError()));
}

void CreateProcessAsTrustedInstaller(DWORD pid, wstring commandLine, bool show)
{
	EnablePrivilege(SE_DEBUG_NAME); 
	EnablePrivilege(SE_IMPERSONATE_NAME);

	ImpersonateSystem();

	HANDLE hTIProcess;
	if ((hTIProcess = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		FALSE,
		pid)) == nullptr)
	{
		throw runtime_error("OpenProcess failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}

	HANDLE hTIToken;
	if (!OpenProcessToken(
		hTIProcess,
		MAXIMUM_ALLOWED,
		&hTIToken))
	{
		CloseHandle(hTIProcess);
		throw runtime_error("OpenProcessToken failed (TrustedInstaller.exe): " + to_string(GetLastError()));
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
		throw runtime_error("DuplicateTokenEx failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}

	EnableAllPrivileges(hDupToken);

	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	if (show) 
	{
		startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
	}
	else 
	{
		startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Winlogon";
	}
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
	if (!CreateProcessWithTokenW(
		hDupToken,
		LOGON_WITH_PROFILE,
		nullptr,
		const_cast<LPWSTR>(commandLine.c_str()),
		CREATE_UNICODE_ENVIRONMENT,
		nullptr,
		nullptr,
		&startupInfo,
		&processInfo))
	{
		throw runtime_error("CreateProcessWithTokenW failed: " + to_string(GetLastError()));
	}
}


void run_as_Ti(wstring commandLine, bool show)
{
	try
	{
		auto pid = StartTrustedInstallerService();
		CreateProcessAsTrustedInstaller(pid, commandLine, show);
	}
	catch (exception e)
	{
		wcout << e.what() << endl;
	}
}

int wmain(int argc, wchar_t* argv[])
{
	wstring commandLine;
	bool show = true;
	if (argc == 1)
	{
		commandLine = L"cmd.exe";
	}
	else if (argc == 2)
	{
		commandLine = argv[1];
	}
	else if (argc == 3)
	{
		commandLine = argv[1];
		show = (bool)_wtoi(argv[2]);
	}
	else
	{
		wcout << L"Usage: " << argv[0] << L"[command] [show_flag]" << endl;
		wcout << L"Error: invalid argument." << endl;
		return 0;
	}

	run_as_Ti(commandLine, show);

	return 0;
}
