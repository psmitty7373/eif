#include "stdafx.h"

#define NOMINMAX
#define SIOCTL_TYPE 40000

#define EIF_32BIT_DLL L"c:\\temp\\eifdll32.dll"
#define EIF_64BIT_DLL L"c:\\temp\\eifdll64.dll"

#define DEBUG

typedef struct _ProcessCallbackInfo {
	HANDLE  parentId;
	HANDLE  processId;
	BOOLEAN create;
} PROCESS_CALLBACK_INFO, *PPROCESS_CALLBACK_INFO;

#define SIZEOF_PROCESS_CALLBACK_INFO sizeof(PROCESS_CALLBACK_INFO)
#define IOCTL_GET_PROCESS_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _CLIENT_ID
{
	UINT64 UniqueProcess;
	UINT64 UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

EXTERN_C LONG WINAPI RtlCreateUserThread(HANDLE,
	PSECURITY_DESCRIPTOR,
	BOOLEAN, SIZE_T,
	PSIZE_T, PSIZE_T,
	PVOID, PVOID,
	PHANDLE, PCLIENT_ID
);

using namespace std;

SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
HANDLE g_StopEvent;
DWORD g_CurrentState = 0;
bool g_SystemShutdown = false;

FILE *file;

int loadDriver() {
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	BOOL status = FALSE;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager)	{
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		string::size_type pos = string(path).find_last_of("\\/");
		strcpy_s(path, string(path).substr(0, pos).c_str());
		strcat_s(path, sizeof(path), "\\agentdrv.sys");
		wchar_t wPath[4096] = { 0 };
		MultiByteToWideChar(0, 0, path, strlen(path), wPath, (int)strlen(path));
		hService = CreateService(hSCManager, L"agentdrv", L"agentdrv", SERVICE_START | SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, wPath, NULL, NULL, NULL, NULL, NULL);
		if (!hService) {
			fprintf(file, "Why? %d", GetLastError());
			if (GetLastError() == ERROR_DUPLICATE_SERVICE_NAME || GetLastError() == ERROR_SERVICE_EXISTS) {
				fprintf(file, "Driver exists, attempting to start.\n");
				CloseServiceHandle(hService);
				hService = OpenService(hSCManager, L"agentdrv", SERVICE_START | SERVICE_QUERY_STATUS);
				if (!hService) {
					fprintf(file, "Unable to open driver service.\n");
					CloseServiceHandle(hService);
					CloseServiceHandle(hSCManager);
					return status;
				}
			}
			else {
				fprintf(file, "Unable to create driver service.\n");
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				return status;
			}
		}
		if (hService) {
			SERVICE_STATUS svcStatus;
			if (QueryServiceStatus(hService, &svcStatus) == FALSE) {
				fprintf(file, "Unable to query driver service status.\n");
			}
			else if (svcStatus.dwCurrentState == SERVICE_RUNNING) {
				fprintf(file, "Driver already running.\n");
				status = TRUE;
			}
			else if (StartService(hService, 0, NULL)) {
				fprintf(file, "Driver started.\n");
				status = TRUE;
			}
			else {
				fprintf(file, "Unable to start driver.\n");
			}
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return status;
		}
	}
	CloseServiceHandle(hSCManager);
	return status;
}

int unloadDriver() {
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager) {
		hService = OpenService(hSCManager, L"agentdrv", DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
		if (hService) {
			ControlService(hService, SERVICE_CONTROL_STOP, &ss);
			SERVICE_STATUS svcStatus;
			while (QueryServiceStatus(hService, &svcStatus) && svcStatus.dwCurrentState != SERVICE_STOPPED) {
				QueryServiceStatus(hService, &svcStatus);
				Sleep(500);
			}
			DeleteService(hService);
		}
		CloseServiceHandle(hService);
	}
	CloseServiceHandle(hSCManager);
	return TRUE;
}

int SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		fprintf(file, "Privilege lookup error.\n");
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		fprintf(file, "Unable to adjust token: %d.\n", GetLastError());
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		fprintf(file, "Failed to set privileges.  Please run as an administrator.");
		return FALSE;
	}
	return TRUE;
}

void inject(DWORD pid)
{
	Sleep(1000);
	fprintf(file, "Injecting: %d.\n", pid);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!process) {
		CloseHandle(process);
		fprintf(file, "Unable to open process.\n");
		return;
	}
	BOOL status;
	BOOL process_is32 = false;
	CLIENT_ID cid;
	IsWow64Process(process, &process_is32);

	char *dllPath;
	fprintf(file, "Process is 32bits? %d\n", process_is32);
	if (process_is32)	
		dllPath = "c:\\temp\\eifdllx32.dll";
	else
		dllPath = "c:\\temp\\eifdllx64.dll";
	fprintf(file, "Injecting... %s in pid... %d\n", dllPath, (int)pid);
	BOOL kernel32Loaded = FALSE;
	MEMORY_BASIC_INFORMATION mbi;
	PBYTE addr = 0;
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	while (addr < sysinfo.lpMaximumApplicationAddress) {
		if (VirtualQueryEx(process, addr, &mbi, sizeof(mbi)) == 0)
			break;
		if (mbi.State == MEM_COMMIT) {
			char modName[MAX_PATH];
			if (GetMappedFileNameA(process, addr, modName, sizeof(modName)) > 0) {
				//fprintf(file, "Module: %s\n", modName);
				if (strstr(modName, "kernel32.dll") != NULL) {
					kernel32Loaded = TRUE;
					break;
				}
			}
		}
		addr += mbi.RegionSize;
	}
	if (process && kernel32Loaded && !process_is32) {
		
		HANDLE thread = nullptr;
		HMODULE k32 = GetModuleHandleA("kernel32.dll");
		LPVOID llAddr = (LPVOID)GetProcAddress(k32, "LoadLibraryA");
		LPVOID baseAddr = VirtualAllocEx(process, 0, strlen(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (k32 && llAddr && baseAddr) {
			status = WriteProcessMemory(process, baseAddr, dllPath, strlen(dllPath), NULL);
			if (!status) {
				fprintf(file, "Unable to write to process: %d.\n", pid);
			}
			else {
				RtlCreateUserThread(process, NULL, false, 0, 0, 0, llAddr, baseAddr, &thread, &cid);
				if (!thread) {
					fprintf(file, "Unable to start thread in process: %d.\n", pid);
				}
				else
					fprintf(file, "Injection complete.\n");
			}
		}
		CloseHandle(k32);
		CloseHandle(thread);
	}
	else {
		fprintf(file, "Not injecting...\n");
	}
	CloseHandle(process);
}

void inject_all() {
	DWORD processes[1024], cbNeeded, cProcesses;
	if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
		return;
	cProcesses = cbNeeded / sizeof(DWORD);

	for (unsigned int i = 0; i < cProcesses; i++) {
		if (processes[i] != 0) {
			DWORD_PTR pp = processes[i];
			CloseHandle(CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(inject), reinterpret_cast<LPVOID>(pp), 0, nullptr));
		}
	}
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

int blark() {
	HANDLE pipe = CreateNamedPipe(L"eifagent", PIPE_ACCESS_INBOUND | PIPE_ACCESS_OUTBOUND, PIPE_WAIT, 1, 1024, 1024, 120 * 1000, NULL);
	if (pipe == INVALID_HANDLE_VALUE) {
		fprintf(file, "Unable to create named pipe: %d.\n", GetLastError());
	}
	char data[1024];
	DWORD bytesRead;
	ConnectNamedPipe(pipe, NULL);
	while (1) {
		ReadFile(pipe, data, 1024, &bytesRead, NULL);
		if (bytesRead > 0)
			fprintf(file, "From named pipe: %s.\n", data);
	}
	CloseHandle(pipe);
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
	inject_all();
	while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0)
	{
		if (WaitForSingleObject(kernelEvent, 500) != WAIT_TIMEOUT) {
			ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
			status = DeviceIoControl(driver, IOCTL_GET_PROCESS_INFO, 0, 0, &processCallbackInfo, sizeof(processCallbackInfo), &bytesReturned, &ov);
			status = GetOverlappedResult(driver, &ov, &bytesReturned, TRUE);
			if (processCallbackInfo.create) {
				CloseHandle(CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(inject), processCallbackInfo.processId, 0, nullptr));
			}
			CloseHandle(ov.hEvent);
		}
	}
	CloseHandle(driver);
	unloadDriver();
	fclose(file);
	ReportStatus(SERVICE_STOP_PENDING);
	CloseHandle(g_StopEvent);
	ReportStatus(SERVICE_STOPPED);
}

int main(int argc, char* argv[]) {

	if ((file = _fsopen("C:\\temp\\agentlog.txt", "a+", _SH_DENYWR)) == NULL) {
		return 1;
	}
	/*
	//DWORD pid = atoi(argv[1]);
	HANDLE currentPID = GetCurrentProcess();
	HANDLE token;
	OpenProcessToken(currentPID, 40, &token);
	SetPrivilege(token, L"SeDebugPrivilege", TRUE);
	//cout << "Injecting pid: " << pid << endl;
	//inject(pid);
	cout << "Processes:" << endl;
	inject_all();
	fclose(file);
	Sleep(15000);
	return 0;
	*/
	
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
		return -2; // Other error
}