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

HMODULE WINAPI DetourLoadLibraryW(LPCTSTR a)
{
	FILE *file;
	fopen_s(&file, "C:\\temp\\log.txt", "a+");
	fprintf(file, "LL CALLED!\n");
	fclose(file);
	return fpLoadLibraryW(a);
}

HANDLE WINAPI DetourCreateRemoteThread(HANDLE a, LPSECURITY_ATTRIBUTES b, SIZE_T c, LPTHREAD_START_ROUTINE d, LPVOID e, DWORD f, LPDWORD g)
{
	FILE *file;
	fopen_s(&file, "C:\\temp\\log.txt", "a+");
	fprintf(file, "CRT CALLED!\n");
	fclose(file);
	return fpCreateRemoteThread(a, b, c, d, e, f, g);
}

HANDLE WINAPI DetourCreateRemoteThreadEx(HANDLE a, LPSECURITY_ATTRIBUTES b, SIZE_T c, LPTHREAD_START_ROUTINE d, LPVOID e, DWORD f, LPPROC_THREAD_ATTRIBUTE_LIST g, LPDWORD h)
{
	FILE *file;
	fopen_s(&file, "C:\\temp\\log.txt", "a+");
	fprintf(file, "CRTex CALLED!\n");
	fclose(file);
	return fpCreateRemoteThreadEx(a, b, c, d, e, f, g, h);
}

int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}

int init() {
	FILE *file;
	fopen_s(&file, "C:\\temp\\temp.txt", "a+");
	if (file)
		fprintf(file, "DLL attach function called.\n");
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
	// Create a hook for MessageBoxW, in disabled state.
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
	// Enable the hook for MessageBoxW.
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
	}
	if (file) {
		fprintf(file, "DLL attach complete...\n");
		fclose(file);
	}
	return WaitForSingleObject(INVALID_HANDLE_VALUE, INFINITE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /* lpReserved */)
{
	DisableThreadLibraryCalls(hModule);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		return CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr) > nullptr;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		if (MH_DisableHook(&LoadLibrary) != MH_OK)
			return FALSE;
		if (MH_DisableHook(&MessageBoxW) != MH_OK)
			return FALSE;
		if (MH_DisableHook(&CreateRemoteThread) != MH_OK)
			return FALSE;
		if (MH_DisableHook(&CreateRemoteThreadEx) != MH_OK)
			return FALSE;
		if (MH_Uninitialize() != MH_OK)
			return FALSE;
		return TRUE;
	}
	return TRUE;
}

BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	return DllMain(hinstDLL, fdwReason, lpReserved);
}
