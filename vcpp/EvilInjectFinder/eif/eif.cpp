#include "stdafx.h"
#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <sstream>
#include <codecvt>
#include <TlHelp32.h>
#include <map>
#include <list>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <VersionHelpers.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include "optionparser.h"

#define MAX_PAGE_SIZE 128 * 1024 * 1024
#define SIOCTL_TYPE 40000
#define IOCTL_HELLO CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_OPEN_PID CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

using namespace std;

struct MEMORYPROTTABLE {
	int protCode;
	string tag;
};

static MEMORYPROTTABLE memoryProts[] = {
	{PAGE_EXECUTE, "EXECUTE"},
	{PAGE_EXECUTE_READ, "EXECUTE_READ"},
	{PAGE_EXECUTE_READWRITE, "EXECUTE_READWRITE"},
	{PAGE_EXECUTE_WRITECOPY, "EXECUTE_WRITECOPY"},
	{PAGE_NOACCESS, "NOACCESS"},
	{PAGE_READONLY, "READONLY"},
	{PAGE_READWRITE, "READWRITE"},
	{PAGE_WRITECOPY, "WRITECOPY"}
};

#define MEMORYPROTTABLE_LEN sizeof(memoryProts)/sizeof(memoryProts[0])

string getMemoryProtTag(int code) {
	for (int i = 0; i < MEMORYPROTTABLE_LEN; i++) {
		if (memoryProts[i].protCode == code) {
			return memoryProts[i].tag;
		}
	}
	return NULL;
}

struct PAGE {
#ifdef _WIN64
	MEMORY_BASIC_INFORMATION64 mbi;
	ULONGLONG pageAddress;
#else
	MEMORY_BASIC_INFORMATION32 mbi;
	ULONG pageAddress;
#endif
	string perm;
	wstring module;
	wstring exePath;
	string mz;
	string dos;
	string nops;
	int sigs;
	string md5;
};

struct ARG {
	vector<string> signatures;
	vector<string> permissions;
	LPVOID pageAddress;
	bool signatureMatch;
	bool moduleBacking;
	bool compare;
	bool compareOnly;
	bool useDriver;
	bool writePages;
	string format;
	string outDir;
	string arch;
	HANDLE driver;
};

struct PROCESS {
	PROCESSENTRY32 pe32;
	list<PAGE> pages;
	list<MODULEENTRY32> modules;
	DWORD integrityLevel;
	int codeMatch;
	int codeDiffCnt;
#ifdef _WIN64
	ULONGLONG imageBase;
	ULONGLONG baseOfCode;
#else
	ULONG imageBase;
	ULONG baseOfCode;
#endif
};

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

BOOLEAN loadDriver()
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
		strcat_s(path, sizeof(path), "\\eifdrv.sys");
		wchar_t wPath[MAX_PATH] = { 0 };
		MultiByteToWideChar(0, 0, path, strlen(path), wPath, (int)strlen(path));
		hService = CreateService(hSCManager, L"eifdrv", L"Evil Injection Finder", SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, wPath, NULL, NULL, NULL, NULL, NULL);
		if (!hService)
		{
			if (GetLastError() == ERROR_DUPLICATE_SERVICE_NAME) {
				hService = OpenService(hSCManager, L"eifdrv", SERVICE_START | DELETE | SERVICE_STOP);
				if (!hService)
					return FALSE;
			}
			else
				return FALSE;
		}
		if (hService)
		{
			if (StartService(hService, 0, NULL))
				return TRUE;
			else
				return FALSE;
		}
		CloseServiceHandle(hSCManager);
		return TRUE;
	} else
		return FALSE;
}

int unloadDriver() {
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager) {
		hService = OpenService(hSCManager, L"eifdrv", SERVICE_START | DELETE | SERVICE_STOP);
		ControlService(hService, SERVICE_CONTROL_STOP, &ss);
		DeleteService(hService);
		CloseServiceHandle(hService);
	}
	CloseServiceHandle(hSCManager);
	return TRUE;
}

//https://forum.tuts4you.com/topic/25035-c-snippet-md5-of-string-using-wincrpyt-api/
string MD5(string input)
{
	HCRYPTPROV CryptProv;
	HCRYPTHASH CryptHash;
	BYTE BytesHash[33];
	DWORD dwHashLen;
	string final;
	if (CryptAcquireContext(&CryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET))
	{
		if (CryptCreateHash(CryptProv, CALG_MD5, 0, 0, &CryptHash))
		{
			if (CryptHashData(CryptHash, (BYTE*)input.c_str(), (DWORD)input.length(), 0))
			{
				if (CryptGetHashParam(CryptHash, HP_HASHVAL, BytesHash, &dwHashLen, 0))
				{
					final.clear();
					string hexcharset = "0123456789ABCDEF";
					for (int j = 0; j < 16; j++)
					{
						final += hexcharset.substr(((BytesHash[j] >> 4) & 0xF), 1);
						final += hexcharset.substr(((BytesHash[j]) & 0x0F), 1);
					}
				}
			}
		}
	}	CryptDestroyHash(CryptHash);
	CryptReleaseContext(CryptProv, 0);
	return final;
}

std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege,	BOOL bEnablePrivilege) {
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

void ReadMem(PROCESS &p, PAGE &page, ARG &sArgs, HANDLE hProc, ULONGLONG baseAddress, SIZE_T regionSize) {
	if (regionSize > MAX_PAGE_SIZE) {
		return;
	}
	string buf;
	buf.resize(regionSize);
	SIZE_T gotBytes;
	BOOLEAN driverSuccess = FALSE;

	// if using driver and process is protected
	if (sArgs.useDriver && (p.integrityLevel == SECURITY_MANDATORY_SYSTEM_RID || p.integrityLevel == SECURITY_MANDATORY_SYSTEM_RID)) {
		DWORD dwBytesRead = 0;
		char respBuffer[50] = { 0 };
		char reqBuffer[256];
		_REQUESTMEMORY req;
		req.dstPID = GetCurrentProcessId();
#ifdef _WIN64
		req.destAddress = (ULONGLONG)sArgs.pageAddress;
#else
		req.destAddress = (ULONG)sArgs.pageAddress;
#endif
		req.srcPageAddress = page.pageAddress;
		req.pageLength = regionSize;
		req.srcPID = p.pe32.th32ProcessID;
		memcpy(reqBuffer, &req, sizeof(req));
		DeviceIoControl(sArgs.driver, IOCTL_OPEN_PID, &reqBuffer, sizeof(req), respBuffer, sizeof(respBuffer), &dwBytesRead, NULL);
		//cout << "spid:" << req.srcPID << " dpid:" << req.dstPID << " daddr:" << req.destAddress << " resp:"<< string_to_hex(string(respBuffer, dwBytesRead)) << " rsize:" << regionSize <<  " ressize:" << buf.size() << endl;
		memcpy(&buf[0], sArgs.pageAddress, regionSize);
		driverSuccess = TRUE;
	}

	if (driverSuccess || ReadProcessMemory(hProc, (LPCVOID)baseAddress, &buf[0], regionSize, &gotBytes)) {
		page.md5 = MD5(buf);

		// check for MZ header
		if (buf.find("MZ") == 0) {
			page.mz = "Yes";
		}
		else
			page.mz = "No";

		// check for dos string
		if (buf.find("This program cannot be run in DOS mode") != string::npos) {
			page.dos = "Yes";
		}
		else
			page.dos = "No";

		// if this page is our image, calculate address to code segment
		if (p.imageBase && page.pageAddress == p.imageBase) {
			IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(&buf[0]);
			if (pNtHdr) {
				p.baseOfCode = p.imageBase + pNtHdr->OptionalHeader.BaseOfCode;
			}
		}

		if (sArgs.compare && p.baseOfCode && page.pageAddress == p.baseOfCode) {
			HANDLE hFile = CreateFileW(page.exePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (hFile != INVALID_HANDLE_VALUE) {
				HANDLE hMapping = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
				LPVOID lpData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
				IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(lpData);
				IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER*)((ULONGLONG)pNtHdr + 0x18 + pNtHdr->FileHeader.SizeOfOptionalHeader);
				for (int section = 0; section < pNtHdr->FileHeader.NumberOfSections; ++section) {
					if (pNtHdr->OptionalHeader.AddressOfEntryPoint >= pSectionHdr->VirtualAddress && pNtHdr->OptionalHeader.AddressOfEntryPoint < pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize) {
						char *codeOffset = (char *)lpData + pSectionHdr->PointerToRawData;
						if (sArgs.writePages) {
							ofstream out;
							char filename[128];
							sprintf_s(filename, sizeof(filename), "%d-%llx.disk.bin", p.pe32.th32ProcessID, baseAddress);
							if (sArgs.outDir[sArgs.outDir.length() - 1] != '\\')
								out.open((sArgs.outDir + "\\" + filename).c_str(), ios::out | ios::binary);
							else
								out.open((sArgs.outDir + filename).c_str(), ios::out | ios::binary);
							out.write(codeOffset, pNtHdr->OptionalHeader.SizeOfCode);
							out.close();
						}
						if (memcmp(codeOffset, &buf[0], pNtHdr->OptionalHeader.SizeOfCode) == 0) {
							p.codeMatch = 1;
						}
						else {
							for (UINT i = 0; i < pNtHdr->OptionalHeader.SizeOfCode; i++) {
								if (*(codeOffset + i) != buf[i])
									p.codeDiffCnt++;
							}
							p.codeMatch = -1;
						}
						break;
					}
					pSectionHdr++;
				}
				UnmapViewOfFile(lpData);
				CloseHandle(hMapping);
				CloseHandle(hFile);
			}
		}

		// search memory for signatures from signature file
		for (vector<string>::iterator it = sArgs.signatures.begin(); it != sArgs.signatures.end(); it++) {
			if (buf.find(it->c_str()) != string::npos) {
				page.sigs++;
			}
			wstring_convert<codecvt_utf16<wchar_t, 0x10ffff, little_endian>> cv;
			wstring wSig(it->begin(), it->end());
			string nWSig = cv.to_bytes(wSig);
			if (buf.find(nWSig) != string::npos) {
				page.sigs++;
			}
		}

		// if writing memory pages, write them
		if (sArgs.writePages && (!sArgs.signatureMatch || page.sigs > 0)) {
			ofstream out;
			char filename[128];
			sprintf_s(filename, sizeof(filename), "%d-%llx.bin", p.pe32.th32ProcessID, baseAddress);
			if (sArgs.outDir[sArgs.outDir.length()-1] != '\\')
				out.open((sArgs.outDir + "\\" + filename).c_str(), ios::out | ios::binary);
			else
				out.open((sArgs.outDir + filename).c_str(), ios::out | ios::binary);
			out.write(buf.c_str(), buf.length());
			out.close();
		}
		page.nops = to_string(count(buf.begin(), buf.end(), '\x90') / regionSize) + '%';
	}
	else {
		page.md5 = "UNABLE TO ACCESS MEMORY!";
	}
}

#ifdef _WIN64
ULONGLONG ScanPage(PROCESS &p, ARG &sArgs, HANDLE hProc, ULONGLONG pageAddress, BOOL processIs32, ULONGLONG minAddress) {
	MEMORY_BASIC_INFORMATION64 mbi;
#else
ULONG ScanPage(PROCESS &p, ARG &sArgs, HANDLE hProc, ULONG pageAddress, BOOL processIs32, ULONG minAddress) {
	MEMORY_BASIC_INFORMATION32 mbi;
#endif
	PAGE page;
	page.dos = "?";
	page.mz = "?";
	page.module = L"";
	page.nops = "?";
	page.sigs = 0;
	if (VirtualQueryEx(hProc, (LPVOID)pageAddress, (PMEMORY_BASIC_INFORMATION)&mbi, sizeof(mbi))) {
#ifdef _WIN64
		ULONGLONG nextRegion = mbi.BaseAddress + mbi.RegionSize;
#else
		ULONG nextRegion = (ULONG)mbi.BaseAddress + mbi.RegionSize;
#endif
		page.pageAddress = pageAddress;

		// get the module name associated with this page
		for (list<MODULEENTRY32>::iterator it = p.modules.begin(); it != p.modules.end(); it++) {
			if (pageAddress >= (ULONGLONG)it->modBaseAddr && pageAddress <= (ULONGLONG)(it->modBaseAddr + it->modBaseSize)) {
				page.module = wstring(it->szModule);
				page.exePath = wstring(it->szExePath);
				break;
			}
		}

		// if only checking for unbacked modules, continue
		if (page.module != L"" && sArgs.moduleBacking)
			return nextRegion;

		if (mbi.Protect != 0 && pageAddress >= minAddress) {
			string protect = "";
			string modifier;
			DWORD perm;
			if (mbi.Protect & 0x100) {
				modifier = "GUARD";
				perm = mbi.Protect ^ 0x100;
				protect = getMemoryProtTag(perm);
			}
			else if (mbi.Protect & 0x200) {
				modifier = "NOCACHE";
				perm = mbi.Protect ^ 0x200;
				protect = getMemoryProtTag(perm);
			}
			else if (mbi.Protect & 0x400) {
				modifier = "WRITECOMBINE";
				perm = mbi.Protect ^ 0x400;
				protect = getMemoryProtTag(perm);
			}
			else
				protect = getMemoryProtTag(mbi.Protect);

			if (find(sArgs.permissions.begin(), sArgs.permissions.end(), protect) != sArgs.permissions.end()) {
				ReadMem(p, page, sArgs, hProc, pageAddress, mbi.RegionSize);
				page.perm = protect;
				page.mbi = mbi;
				if (!sArgs.signatureMatch || page.sigs > 0)
					p.pages.push_back(page);
			}

			// if we're checking for hollowing, make sure to process the base image page
			else if (pageAddress == p.imageBase) {
				ReadMem(p, page, sArgs, hProc, pageAddress, mbi.RegionSize);
			}
		}
		return nextRegion;
	}
	else {
		return -1;
	}
}

void ScanProcesses(map<int, PROCESS> &processes, ARG &sArgs, int pid) {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	HANDLE processSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// iterate through processes
	if (Process32First(processSnap, &pe32)) {
		while (Process32Next(processSnap, &pe32)) {
			if (pid != 0 && pe32.th32ProcessID != pid) {
				continue;
			}
			PROCESS p;
			MODULEENTRY32 me32;
			HANDLE hProc;
			p.pe32 = pe32;
			p.imageBase = NULL;
			p.baseOfCode = NULL;
			p.codeMatch = 0;
			p.codeDiffCnt = 0;
			me32.dwSize = sizeof(MODULEENTRY32);
			HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
			// build list of modules
			if (hModuleSnap && Module32First(hModuleSnap, &me32)) {
				do {
					p.modules.push_back(me32);
				} while (Module32Next(hModuleSnap, &me32));
			}
			CloseHandle(hModuleSnap);

			// open process
			if (IsWindows8OrGreater()) {
				hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pe32.th32ProcessID);
				if (!hProc) {
					hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pe32.th32ProcessID);
				}
			}
			else {
				hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pe32.th32ProcessID);
				if (!hProc) {
					hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pe32.th32ProcessID);
				}
			}

			if (hProc) {
				HANDLE token;
				DWORD size = 0;

				// get process integrity level
				if (OpenProcessToken(hProc, TOKEN_QUERY, &token)) {
					if (!GetTokenInformation(token, TokenIntegrityLevel, NULL, size, &size)) {
						if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
							BYTE* pbIL = new BYTE[size];
							if (pbIL) {
								TOKEN_MANDATORY_LABEL* pTML = (TOKEN_MANDATORY_LABEL*)pbIL;
								DWORD dwSize2;
								if (GetTokenInformation(token, TokenIntegrityLevel, pTML, size, &dwSize2) && dwSize2 <= size) {
									p.integrityLevel = *GetSidSubAuthority(pTML->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTML->Label.Sid) - 1));

								}
							}
						}
					}
				}

				BOOL process_is32 = false;

				// check process bits
				IsWow64Process(hProc, &process_is32);
#ifdef _WIN64
				ULONGLONG minAddress, maxAddress, pageAddress;
				minAddress = (ULONGLONG)si.lpMinimumApplicationAddress;
				pageAddress = minAddress;
				if (process_is32 && (ULONGLONG)si.lpMaximumApplicationAddress > 0xFFFFFFFF) {
					maxAddress = 0xFFFEFFFF;
				}
				else
					maxAddress = (ULONGLONG)si.lpMaximumApplicationAddress;
#else
				// make sure process is 32-bit, since we're using 32-bit eif
				if (!process_is32 && si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL) {
					cerr << "Process PID " << pe32.th32ProcessID << " is 64-bit and this is a 32-bit version of eif!" << endl;
					continue;
				}
				ULONG minAddress, maxAddress, pageAddress;
				minAddress = (ULONG)si.lpMinimumApplicationAddress;
				maxAddress = (ULONG)si.lpMaximumApplicationAddress;
				pageAddress = minAddress;
#endif
				// get base address for process image
				HMODULE hMod;
				DWORD cbNeeded;
				if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded)) {
					p.imageBase = (ULONGLONG)hMod;
					ScanPage(p, sArgs, hProc, p.imageBase, process_is32, minAddress);
				}

				// if checking code segments, don't process other stuff
				if (sArgs.compare) {
					ScanPage(p, sArgs, hProc, p.baseOfCode, process_is32, minAddress);
				}
				else {
					// walk process memory regions
					while (pageAddress < maxAddress) {
#ifdef _WIN64
						ULONGLONG nextRegion = ScanPage(p, sArgs, hProc, pageAddress, process_is32, minAddress);
#else
						ULONG nextRegion = ScanPage(p, sArgs, hProc, pageAddress, process_is32, minAddress);
#endif
						if (nextRegion < 0) {
							break;
						}
						pageAddress = nextRegion;
					}
				}
			}
			CloseHandle(hProc);

			// save process for output
			processes[pe32.th32ProcessID] = p;
		}
	}
	CloseHandle(processSnap);
}

string convertBytes(SIZE_T regionSize) {
	stringstream ss;
	if (regionSize > 1099511627776) {
		ss << fixed << setprecision(2) << (regionSize / 1099511627776.) << "TB";
	}
	else if (regionSize > 1073741824) {
		ss << fixed << setprecision(2) << (regionSize / 1073741824.) << "GB";
	}
	else if (regionSize > 1048576) {
		ss << fixed << setprecision(2) << (regionSize / 1048576.) << "MB";
	}
	else if (regionSize > 1024) {
		ss << fixed << setprecision(2) << (regionSize / 1024.) << "KB";
	}
	else {
		ss << fixed << setprecision(2) << regionSize << "b";
	}
	return ss.str();
}

struct Arg : public option::Arg
{
	static option::ArgStatus Required(const option::Option& option, bool msg)
	{
		if (option.arg != 0)
			return option::ARG_OK;
		if (msg) cerr << "Option '" << option.name << "' requires an argument" << endl;
		return option::ARG_ILLEGAL;
	}
	static option::ArgStatus Numeric(const option::Option& option, bool msg)
	{
		char* endptr = 0;
		if (option.arg != 0 && strtol(option.arg, &endptr, 10)) {};
		if (endptr != option.arg && *endptr == 0)
			return option::ARG_OK;

		if (msg) cerr << "Option '" << option.name << "' requires a numeric argument" << endl;
		return option::ARG_ILLEGAL;
	}
};

enum  optionIndex { UNKNOWN, HELP, BACKING, COMPARE, COMPAREONLY, DRIVER, FORMAT, OUTDIR, PERM, PID, SIGFILE, SIGMATCH };
const option::Descriptor usage[] =
{
	{ UNKNOWN, 0,"" , ""    , Arg::None, "Evil Injection Finder (EIF)\n"
	"Helping you find evil injections since 2017.\n"
	"USAGE: example [options]\n\n"
	"Options:" },
	{ HELP, 0,"h" , "help", Arg::None, "  -h  \tPrint usage and exit." },
	{ BACKING, 0,"b" , "backing", Arg::None, "  -b  \tOnly show matches without file backing." },
	{ COMPARE, 0,"c" , "compare", Arg::None, "  -c  \tCompare in-memory code segment with on-disk code segment." },
	{ COMPAREONLY, 0,"C" , "compareonly", Arg::None, "  -C  \tOnly show processes with non-matching code segments." },
	{ DRIVER, 0,"d" , "driver", Arg::None, "  -d  \tUse kernel driver to access protected process memory." },
	{ FORMAT, 0, "f", "format", Arg::Required, "  -f <format> \tOutput format (CSV,)." },
	{ PERM, 0, "i", "perm", Arg::Required, "  -i  \tSearch pages with specific permissions. Default is EXECUTE_READWRITE." },
	{ SIGFILE, 0, "s", "sigfile", Arg::Required, "  -s <sigfile.txt> \tUse a signature file." },
	{ SIGMATCH, 0, "S", "sigmatch", Arg::None, "  -S  \tOnly show memory pages with signature matches." },
	{ PID, 0, "p", "pid", Arg::Numeric, "  -p  \tSpecify a single PID."},
	{ OUTDIR, 0, "w", "outdir", Arg::Required, "  -w <c:\\outdir\\> \tWrite matching pages to disk." },
	{ UNKNOWN, 0,"" ,  ""   , Arg::None, "\nExamples:\n"
	"  eif.exe -p 123 -s sigs.txt -S -b -i EXECUTE_READWRITE\n\n"
	"Available Permissions: EXECUTE, EXECUTE_READ, EXECUTE_READWRITE,\n"
	"EXECUTE_WRITECOPY, NOACCESS, READWRITE, WRITECOPY, READONLY\n"},
	{ 0,0,0,0,0,0 }
};

int main(int argc, char* argv[])
{
	DWORD pid = 0;
	HANDLE currentPID = GetCurrentProcess();
	HANDLE token;
	ARG sArgs;
	map<int, PROCESS> processes;
	//options parsing
	sArgs.signatureMatch = false;
	sArgs.compare = false;
	sArgs.compareOnly = false;
	sArgs.moduleBacking = false;
	sArgs.useDriver = false;
	sArgs.writePages = false;
	sArgs.format = "STD";
#ifdef _WIN64
	sArgs.arch = "64bit";
#else
	sArgs.arch = "32bit";
#endif
	argc -= (argc>0); argv += (argc>0);
	option::Stats  stats(usage, argc, argv);
	std::vector<option::Option> options(stats.options_max);
	std::vector<option::Option> buffer(stats.buffer_max);
	option::Parser parse(usage, argc, argv, &options[0], &buffer[0]);
	if (parse.error())
		return 1;
	if (options[HELP]) {
		clog << "+------------------------------------------------+" << endl;
		clog << "| Evil Inject Finder                             |" << endl;
		clog << "| by: Phillip Smith                              |" << endl;
		clog << "+------------------------------------------------+" << endl << endl;
		option::printUsage(std::cout, usage);
		return 0;
	}
	if (!options[PERM])
		sArgs.permissions.push_back("EXECUTE_READWRITE");
	for (int i = 0; i < parse.optionsCount(); ++i)
	{
		option::Option& opt = buffer[i];
		switch (opt.index())
		{
		case BACKING:
			sArgs.moduleBacking = true;
			break;
		case COMPAREONLY:
			sArgs.compareOnly = true;
		case COMPARE:
			sArgs.compare = true;
			break;
		case FORMAT:
			if (string(opt.arg) == "CSV") {
				sArgs.format = "CSV";
			}
			break;
		case PERM:
			sArgs.permissions.push_back(string(opt.arg));
			break;
		case PID:
			pid = (DWORD)atoi(opt.arg);
			break;
		case OUTDIR:
			sArgs.outDir = string(opt.arg);
			if (GetFileAttributesA(sArgs.outDir.c_str()) != INVALID_FILE_ATTRIBUTES && (GetFileAttributesA(sArgs.outDir.c_str()) & FILE_ATTRIBUTE_DIRECTORY))
				sArgs.writePages = true;
			else {
				cerr << "Output directory does not exist!" << endl;
				return(1);
			}
			break;
		case SIGFILE:
			try {
				ifstream sigsFile(opt.arg);
				if (sigsFile.good()) {
					copy(istream_iterator<string>(sigsFile), istream_iterator<string>(), back_inserter(sArgs.signatures));
				}
				else
					sigsFile.exceptions(ifstream::failbit | ifstream::badbit);
			}
			catch (ifstream::failure e) {
				cerr << "Unable to open signature file!" << endl;
				return(1);
			}
			break;
		case SIGMATCH:
			sArgs.signatureMatch = true;
			break;
		case DRIVER:
			sArgs.useDriver = true;
			break;
		}
	}
	for (option::Option* opt = options[UNKNOWN]; opt; opt = opt->next())
		std::cerr << "Unknown option: " << std::string(opt->name, opt->namelen) << "\n";
	for (int i = 0; i < parse.nonOptionsCount(); ++i)
		std::cerr << "Non-option #" << i << ": " << parse.nonOption(i) << "\n";
	OpenProcessToken(currentPID, 40, &token);
	SetPrivilege(token, L"SeDebugPrivilege", TRUE);
	if (options[DRIVER]) {
		if (!loadDriver()) {
			cerr << "Unable to load kernel driver." << endl;
			unloadDriver();
			return 0;
		}
		sArgs.useDriver = true;
		sArgs.driver = CreateFile(L"\\\\.\\eifdrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		HANDLE h = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (128*1024*1024), NULL);
		sArgs.pageAddress = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, (128 * 1024 * 1024));
	}
	ScanProcesses(processes, sArgs, pid);
	for (map<int, PROCESS>::iterator it = processes.begin(); it != processes.end(); it++) {
		if (it->second.pages.size() > 0) {
			if (sArgs.compareOnly && it->second.codeMatch == 1)
				continue;
			if (sArgs.format == "STD") {
				wcout << "Analysing PID: " << it->first << " : " << it->second.pe32.szExeFile << endl;
				if (it->second.integrityLevel == SECURITY_MANDATORY_SYSTEM_RID || it->second.integrityLevel == SECURITY_MANDATORY_SYSTEM_RID)
					wcout << "ATTENTION! PID is protected!" << endl;
				if (sArgs.compare) {
					if (it->second.codeMatch == -1)
						wcout << "Codematch: WARNING! NON-MATCHING code segment. Bytes diff: " << it->second.codeDiffCnt << endl;
					else if (it->second.codeMatch == 0)
						wcout << "Codematch: Unable to validate code segment." << endl;
					else
						wcout << "Codematch: Matching code segment." << endl;
				}
				cout << "+" << string(153, '-') << "+" << endl;
				cout << "|" << setw(13) << right << "Address" << " | " << setw(17) << left << "Permissions" << " | " << setw(13) << right << "Size" << " | " << setw(39) << left << "Module" << " | " << setw(3) << "MZ" << " | " << setw(3) << "DOS" << " | " << setw(4) << "Nops" << " | " << setw(4) << "Sigs" << " | " << setw(32) << "MD5" << " |" << endl;
				cout << "+" << string(153, '-') << "+" << endl;
				for (list<PAGE>::iterator it2 = it->second.pages.begin(); it2 != it->second.pages.end(); it2++) {
					cout << "|" << setw(13) << right << hex << it2->pageAddress << " | " << setw(17) << left << it2->perm << " | " << setw(13) << right << convertBytes(it2->mbi.RegionSize) << " | ";
					wcout << setw(39) << left << it2->module.substr(0, 39);
					cout << " | " << setw(3) << it2->mz << " | " << setw(3) << it2->dos << " | " << setw(4) << it2->nops << " | " << setw(4) << it2->sigs << " | " << setw(32) << it2->md5 << " |" << endl;
				}
				cout << "+" << string(153, '-') << "+" << endl << endl;
			}
			else if (sArgs.format == "CSV") {
				cout << "PID,Page Address,Permissions,Region Size,Module,MZ,DOS,NOPs,Sigs,MD5" << endl;
				for (list<PAGE>::iterator it2 = it->second.pages.begin(); it2 != it->second.pages.end(); it2++) {
					cout << dec << it->first << "," << hex << it2->pageAddress << dec << "," << it2->perm << "," << convertBytes(it2->mbi.RegionSize) << ",";
					wcout << it2->module;
					cout << "," << it2->mz << "," << it2->dos << "," << it2->nops << "," << it2->sigs << "," << it2->md5 << endl;
				}
			}
		}
	}
	if (options[DRIVER]) {
		CloseHandle(sArgs.driver);
		if (!unloadDriver()) {
			cerr << "Unable to unload kernel driver!" << endl << endl;
		}
	}
    return 0;
}