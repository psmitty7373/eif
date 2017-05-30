#include "stdafx.h"

#define NOMINMAX
#define SIOCTL_TYPE 40000

#define EIF_32BIT_DLL L"c:\\temp\\eifdll32.dll"
#define EIF_64BIT_DLL L"c:\\temp\\eifdll64.dll"

typedef struct _ProcessCallbackInfo {
	HANDLE  parentId;
	HANDLE  processId;
	BOOLEAN create;
} PROCESS_CALLBACK_INFO, *PPROCESS_CALLBACK_INFO;

#define SIZEOF_PROCESS_CALLBACK_INFO sizeof(PROCESS_CALLBACK_INFO)
#define IOCTL_GET_PROCESS_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/*
NTSTATUS WINAPI RtlCreateUserThread(
	HANDLE hProcess,
	SECURITY_DESCRIPTOR* pSec,
	BOOLEAN fCreateSuspended,
	ULONG StackZeroBits,
	SIZE_T* StackReserved,
	SIZE_T* StackCommit,
	void*,
	void*,
	HANDLE* pThreadHandle,
	CLIENT_ID* pResult);
	*/

EXTERN_C LONG WINAPI RtlCreateUserThread(HANDLE,
	PSECURITY_DESCRIPTOR,
	BOOLEAN, ULONG,
	PULONG, PULONG,
	PVOID, PVOID,
	PHANDLE, PCLIENT_ID);
EXTERN_C LONG WINAPI NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

using namespace std;

SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
HANDLE g_StopEvent;
DWORD g_CurrentState = 0;
bool g_SystemShutdown = false;

FILE *file;

int loadDriver() {
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		string::size_type pos = string(path).find_last_of("\\/");
		strcpy_s(path, string(path).substr(0, pos).c_str());
		strcat_s(path, sizeof(path), "\\agentdrv.sys");
		wchar_t wPath[4096] = { 0 };
		MultiByteToWideChar(0, 0, path, strlen(path), wPath, (int)strlen(path));
		wcerr << wPath << endl;
		hService = CreateService(hSCManager, L"agentdrv", L"agentdrv", SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, wPath, NULL, NULL, NULL, NULL, NULL);
		if (!hService) {
			cerr << "Service create problem." << endl;
			if (GetLastError() == ERROR_DUPLICATE_SERVICE_NAME) {
				hService = OpenService(hSCManager, L"agentdrv", SERVICE_START | DELETE | SERVICE_STOP);
				if (!hService)
					return FALSE;
			}
			else
				return FALSE;
		}
		if (hService) {
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

bool inject(DWORD pid)
{
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!process) {
		fprintf(file, "Unable to open process.\n");
		return false;
	}
	BOOL status;
	BOOL process_is32 = false;
	HANDLE thread;
	CLIENT_ID cid;
	IsWow64Process(process, &process_is32);
	char *dllName;
	if (process_is32)	
		dllName = "c:\\temp\\eifdllx32.dll";
	else
		dllName = "c:\\temp\\eifdllx64.dll";
	fprintf(file, "Injecting... %s in pid... %d\n", dllName, (int)pid);
	if (process) {
		LPVOID llAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		LPVOID baseAddress = VirtualAllocEx(process, 0, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		status = WriteProcessMemory(process, baseAddress, dllName, strlen(dllName), NULL);
		if (!status) {
			fprintf(file, "Unable to write to process: %d.\n", pid);
			return false;
		}
		RtlCreateUserThread(process, NULL, false, 0, 0, 0, llAddr, baseAddress, &thread, &cid);
		//thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)llAddr, baseAddress, NULL, 0);
		if (!thread) {
			wchar_t buf[256];
			FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, 256, NULL);
			fprintf(file, "Unable to start thread in process: %d.\n", pid, buf);
			fwprintf(file, L"This: %s", buf);
			return false;
		}
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
		CloseHandle(process);
		fprintf(file, "Injection complete.\n");
		return true;
	}
	return false;
}

void ReportStatus(DWORD state) {
	g_CurrentState = state;
	SERVICE_STATUS serviceStatus = {
		SERVICE_WIN32_OWN_PROCESS,
		g_CurrentState,
		state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
		NO_ERROR,
		0,
		0,
		0,
	};
	SetServiceStatus(g_ServiceStatusHandle, &serviceStatus);
}

void ReportErrorStatus(DWORD errorCode) {
	g_CurrentState = SERVICE_STOPPED;
	SERVICE_STATUS serviceStatus = {
		SERVICE_WIN32_OWN_PROCESS,
		g_CurrentState,
		0,
		ERROR_SERVICE_SPECIFIC_ERROR,
		errorCode,
		0,
		0,
	};
	SetServiceStatus(g_ServiceStatusHandle, &serviceStatus);
}

DWORD WINAPI HandlerEx(DWORD control, DWORD eventType, void *eventData, void *context) {
	switch (control) {
	case SERVICE_CONTROL_SHUTDOWN:
		g_SystemShutdown = true;
	case SERVICE_CONTROL_STOP:
		ReportStatus(SERVICE_STOP_PENDING);
		SetEvent(g_StopEvent);
		break;
	default:
		ReportStatus(g_CurrentState);
		break;
	}
	return NO_ERROR;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	OVERLAPPED ov = { 0 };
	BOOL status;
	DWORD bytesReturned;
	HANDLE currentPID = GetCurrentProcess();
	HANDLE token;
	HANDLE kernelEvent;
	PROCESS_CALLBACK_INFO processCallbackInfo;

	g_ServiceStatusHandle = RegisterServiceCtrlHandlerEx(_T("eifagent"), &HandlerEx, NULL);
	ReportStatus(SERVICE_START_PENDING);
	g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	ReportStatus(SERVICE_RUNNING);

	OpenProcessToken(currentPID, 40, &token);
	SetPrivilege(token, L"SeDebugPrivilege", TRUE);
	if (!loadDriver()) {
		fprintf(file, "Unable to load kernel driver.\n");
		Sleep(1000 * 5);
		unloadDriver();
		ReportStatus(SERVICE_STOP_PENDING);
		CloseHandle(g_StopEvent);
		ReportStatus(SERVICE_STOPPED);
	}
	HANDLE driver = CreateFile(L"\\\\.\\agentdrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (driver == INVALID_HANDLE_VALUE) {
		fprintf(file, "Driver not found.\n");
		ReportStatus(SERVICE_STOP_PENDING);
		CloseHandle(g_StopEvent);
		ReportStatus(SERVICE_STOPPED);
	}
	kernelEvent = OpenEvent(SYNCHRONIZE, FALSE, L"Global\\EIFProcEvent");
	if (!kernelEvent) {
		fprintf(file, "Unable to open event.\n");
		ReportStatus(SERVICE_STOP_PENDING);
		CloseHandle(g_StopEvent);
		ReportStatus(SERVICE_STOPPED);
	}
	while (WaitForSingleObject(g_StopEvent, 3000) != WAIT_OBJECT_0)
	{
		ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		DWORD result = WaitForSingleObject(kernelEvent, INFINITE);
		status = DeviceIoControl(driver, IOCTL_GET_PROCESS_INFO, 0, 0, &processCallbackInfo, sizeof(processCallbackInfo), &bytesReturned, &ov);
		status = GetOverlappedResult(driver, &ov, &bytesReturned, TRUE);
		if (processCallbackInfo.create) {
			fprintf(file, "CREATE EVENT! %d\n", processCallbackInfo.processId);
			inject((DWORD)processCallbackInfo.processId);
		}
		CloseHandle(ov.hEvent);
	}
	unloadDriver();
	CloseHandle(file);
	ReportStatus(SERVICE_STOP_PENDING);
	CloseHandle(g_StopEvent);
	ReportStatus(SERVICE_STOPPED);
}

int main() {
	fopen_s(&file, "C:\\temp\\agentlog.txt", "a+");
	SERVICE_TABLE_ENTRY serviceTable[] = {
		{ _T(""), &ServiceMain },
		{ NULL, NULL }
	};

	if (StartServiceCtrlDispatcher(serviceTable))
		return 0;
	else if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
		cerr << "This agent must be started as a service." << endl;
		return -1; // Program not started as a service.
	} else
		return -2; // Other error.
}