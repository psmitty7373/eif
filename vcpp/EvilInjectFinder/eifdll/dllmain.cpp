#include "stdafx.h"
#include "MinHook.h"
#include <windows.h>
#include <stdio.h>

#if defined _M_X64
#pragma comment(lib, "MinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "MinHook.x86.lib")
#endif

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}
typedef HMODULE (WINAPI *LOADLIBRARYW)(LPCWSTR);
typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI *CREATEREMOTETHREADEX)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
LOADLIBRARYW fpLoadLibraryW = NULL;
CREATEREMOTETHREAD fpCreateRemoteThread = NULL;
CREATEREMOTETHREADEX fpCreateRemoteThreadEx = NULL;
MESSAGEBOXW fpMessageBoxW = NULL;
HANDLE die, initThread;

HMODULE WINAPI DetourLoadLibraryW(LPCTSTR a)
{
	DWORD pid = GetCurrentProcessId();
	return fpLoadLibraryW(a);
}

HANDLE WINAPI DetourCreateRemoteThread(HANDLE a, LPSECURITY_ATTRIBUTES b, SIZE_T c, LPTHREAD_START_ROUTINE d, LPVOID e, DWORD f, LPDWORD g)
{
	return fpCreateRemoteThread(a, b, c, d, e, f, g);
}

HANDLE WINAPI DetourCreateRemoteThreadEx(HANDLE a, LPSECURITY_ATTRIBUTES b, SIZE_T c, LPTHREAD_START_ROUTINE d, LPVOID e, DWORD f, LPPROC_THREAD_ATTRIBUTE_LIST g, LPDWORD h)
{
	return fpCreateRemoteThreadEx(a, b, c, d, e, f, g, h);
}

int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}

int init() {
	/*
	if (MH_Initialize() != MH_OK)
	{
		return FALSE;
	}
	if (MH_CreateHookApiEx(L"kernel32", "LoadLibraryW", &DetourLoadLibraryW, &fpLoadLibraryW) != MH_OK)
	{
		return FALSE;
	}
	if (MH_CreateHookApiEx(L"kernel32", "CreateRemoteThread", &DetourCreateRemoteThread, &fpCreateRemoteThread) != MH_OK)
	{
		return FALSE;
	}
	if (MH_CreateHookApiEx(L"user32", "MessageBoxW", &DetourMessageBoxW, &fpMessageBoxW) != MH_OK)
	{
		return FALSE;
	}
	if (MH_CreateHookApiEx(L"kernel32", "CreateRemoteThreadEx", &DetourCreateRemoteThreadEx, &fpCreateRemoteThreadEx) != MH_OK)
	{
		return FALSE;
	}
	if (MH_EnableHook(&LoadLibraryW) != MH_OK)
	{
		return FALSE;
	}
	if (MH_EnableHook(&MessageBoxW) != MH_OK)
	{
		return FALSE;
	}
	if (MH_EnableHook(&CreateRemoteThread) != MH_OK)
	{
		return FALSE;
	}
	if (MH_EnableHook(&CreateRemoteThreadEx) != MH_OK)
	{
		return FALSE;
	}*/
	while (WaitForSingleObject(die, 500) != WAIT_OBJECT_0) {
		Sleep(1000);
	}
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /* lpReserved */)
{
	DisableThreadLibraryCalls(hModule);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		die = CreateEvent(0, TRUE, FALSE, 0);
		//initThread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr);
		//return initThread > nullptr;
		return TRUE;
	case DLL_PROCESS_DETACH:
		SetEvent(die);
		if (WaitForSingleObject(initThread, 5000) == WAIT_TIMEOUT)
			TerminateThread(initThread, 0);
		CloseHandle(initThread);
		CloseHandle(die);
		/*
		if (MH_DisableHook(&MessageBoxW) != MH_OK)
			return FALSE;
		if (MH_DisableHook(&LoadLibrary) != MH_OK)
			return FALSE;
		if (MH_DisableHook(&CreateRemoteThread) != MH_OK)
			return FALSE;
		if (MH_DisableHook(&CreateRemoteThreadEx) != MH_OK)
			return FALSE;
		if (MH_Uninitialize() != MH_OK)
			return FALSE;*/
		return TRUE;
	}
	return TRUE;
}

BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	return DllMain(hinstDLL, fdwReason, lpReserved);
}
