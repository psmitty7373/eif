#include "stdafx.h"

#define NOMINMAX
#define SIOCTL_TYPE 40000
#define IOCTL_HELLO CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_OPEN_PID CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

using namespace std;

typedef struct _REGISTER_EVENT
{
	HANDLE  hEvent;
	LARGE_INTEGER DueTime;
} REGISTER_EVENT, *PREGISTER_EVENT;

#define SIZEOF_REGISTER_EVENT sizeof(REGISTER_EVENT)
#define IOCTL_REGISTER_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
	ULONG srcPID;
	ULONG dstPID;
#ifdef _WIN64
	ULONGLONG srcPageAddress;
	ULONGLONG destAddress;
#else
	ULONG srcPageAddress;
	ULONG destAddress;
#endif
	SIZE_T pageLength;
} _REQUESTMEMORY;

int loadDriver()
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)
	{
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		string::size_type pos = string(path).find_last_of("\\/");
		strcpy_s(path, string(path).substr(0, pos).c_str());
		strcat_s(path, sizeof(path), "\\agentdrv.sys");
		wchar_t wPath[4096] = { 0 };
		MultiByteToWideChar(0, 0, path, strlen(path), wPath, (int)strlen(path));
		wcerr << wPath << endl;
		hService = CreateService(hSCManager, L"agentdrv", L"agentdrv", SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, wPath, NULL, NULL, NULL, NULL, NULL);
		if (!hService)
		{
			cerr << "Service create problem." << endl;
			if (GetLastError() == ERROR_DUPLICATE_SERVICE_NAME) {
				hService = OpenService(hSCManager, L"agentdrv", SERVICE_START | DELETE | SERVICE_STOP);
				if (!hService)
					return FALSE;
			}
			else
				return FALSE;
		}
		if (hService)
		{
			cerr << "Starting service." << endl;
			if (StartService(hService, 0, NULL))
				return TRUE;
			else
				return FALSE;
		}
		CloseServiceHandle(hSCManager);
		return TRUE;
	}
	else
		return FALSE;
}

int unloadDriver() {
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager) {
		hService = OpenService(hSCManager, L"agentdrv", SERVICE_START | DELETE | SERVICE_STOP);
		ControlService(hService, SERVICE_CONTROL_STOP, &ss);
		DeleteService(hService);
		CloseServiceHandle(hService);
	}
	CloseServiceHandle(hSCManager);
	return TRUE;
}

int SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		wcerr << "LookupPrivilegeValue error: " << GetLastError() << endl;
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		wcerr << "AdjustTokenPrivileges error: " << GetLastError() << endl;
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		cerr << "Failed to set privileges.  Please run as an administrator." << endl;
		return FALSE;
	}
	return TRUE;
}

int main()
{
	BOOL bStatus;
	DWORD pid = 0;
	HANDLE currentPID = GetCurrentProcess();
	HANDLE token;
	ULONG ulReturnedLength;
	REGISTER_EVENT registerEvent;
	FLOAT fDelay = 3;

	OpenProcessToken(currentPID, 40, &token);
	SetPrivilege(token, L"SeDebugPrivilege", TRUE);

	if (!loadDriver()) {
		cerr << "Unable to load kernel driver." << endl;
		Sleep(1000 * 5);
		unloadDriver();
		return 0;
	}
	cerr << "DRIVER LOADED!";

	HANDLE driver = CreateFile(L"\\\\.\\agentdrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (driver == INVALID_HANDLE_VALUE) {
		cerr << "Driver not found." << endl;
		return 0;
	}

	registerEvent.DueTime.QuadPart = -((LONGLONG)fDelay * 10.0E6);
	registerEvent.hEvent = NULL;
	while (!_kbhit()) {
		bStatus = DeviceIoControl(driver, IOCTL_REGISTER_EVENT, &registerEvent,	SIZEOF_REGISTER_EVENT, NULL, 0, &ulReturnedLength, NULL);
		if (!bStatus) {
			cerr << "Ioctl failed with code: " << GetLastError() << endl;
			break;
		}
		cout << "Event occurred." << endl;
	}

	/*
	DWORD dwBytesRead = 0;
	char respBuffer[50] = { 0 };
	char reqBuffer[256];
	_REQUESTMEMORY req;
	req.dstPID = GetCurrentProcessId();
#ifdef _WIN64
	req.destAddress = 0;
#else
	req.destAddress = (ULONG)sArgs.pageAddress;
#endif
	req.srcPageAddress = 0;
	req.pageLength = 0;
	req.srcPID = 0;
	memcpy(reqBuffer, &req, sizeof(req));
	DeviceIoControl(driver, IOCTL_OPEN_PID, &reqBuffer, sizeof(req), respBuffer, sizeof(respBuffer), &dwBytesRead, NULL);
	*/
	Sleep(1000 * 5);
	unloadDriver();
    return 0;
}

