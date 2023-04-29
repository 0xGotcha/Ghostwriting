#include <iostream>
#include <Windows.h>
#include <string_view>
#include <psapi.h>
#include <TlHelp32.h>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/color.h>

//using namespace vManager::memory::noPool;

namespace io {


	
	template<typename... Args>

	void log(const std::string_view str, Args... params) {

		static auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(handle, FOREGROUND_GREEN);
		fmt::print("[+] ");
		SetConsoleTextAttribute(handle, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

		std::string msg{ str };
		msg.append("\n");
		fmt::print(msg, std::forward<Args>(params)...);

	}

	template<typename... Args>
	void log_error(const std::string_view str, Args... params) {

		static auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(handle, FOREGROUND_RED);
		fmt::print("[+] ");
		SetConsoleTextAttribute(handle, FOREGROUND_RED | FOREGROUND_INTENSITY | FOREGROUND_RED);

		std::string msg{ str };
		msg.append("\n");
		fmt::print(msg, std::forward<Args>(params)...);

	}

}

HANDLE CreateStealthThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);


// https://stackoverflow.com/questions/52988769/writing-own-memmem-for-windows
void* memmem(BYTE* haystack, size_t haystack_len, const char* needle, const size_t needle_len)
{
	if (haystack == NULL) return NULL; // or assert(haystack != NULL);
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL; // or assert(needle != NULL);
	if (needle_len == 0) return NULL;

	for (const char* h = (const char*)haystack; haystack_len >= needle_len; ++h, --haystack_len) {
		if (!memcmp(h, needle, needle_len)) {
			return (void*)h;
		}
	}
	return NULL;
}

//https://blog.sevagas.com/IMG/pdf/code_injection_series_part5.pdf

const char* JMP_0_OPCODE = "\xeb\xfe"; //loop gadget
const char* MOV_PTRRDX_RAX_RET = "\x48\x89\x02\xC3";

typedef struct _REMOTE_THREAD_CONTEXT_MANIPULATION {
	DWORD64 threadId;
	HANDLE hProcess;
	HANDLE hThread;
	CONTEXT savedThreadContext;
	DWORD64 writeGadgetAddr;
	DWORD64 jmp0GadgetAddr;
	DWORD64 jmp0StackAddr;
	BOOL createNewThread;
}REMOTE_THREAD_CONTEXT_MANIPULATION, * PREMOTE_THREAD_CONTEXT_MANIPULATION;


void WriteToRemoteThread(PREMOTE_THREAD_CONTEXT_MANIPULATION threadManip, ULONG_PTR addressToWrite, DWORD64 valueToWrite) {
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(threadManip->hThread, &threadContext);

	threadContext.Rax = (ULONG_PTR)valueToWrite;
	threadContext.Rdx = (ULONG_PTR)addressToWrite;
	threadContext.Rip = (ULONG_PTR)threadManip->writeGadgetAddr; // Gadget is: MOV [RDX], RAX; RET
	threadContext.Rsp = (ULONG_PTR)threadManip->jmp0StackAddr; // So RET will return to JMP 0 infinit loop

	SetThreadContext(threadManip->hThread, &threadContext);

	ResumeThread(threadManip->hThread);

	Sleep(2);
	SuspendThread(threadManip->hThread);
}
BOOL InitThreadManipulation(HANDLE hProcess, PREMOTE_THREAD_CONTEXT_MANIPULATION threadManip, DWORD remoteThreadId) {
	memset(threadManip, 0, sizeof(REMOTE_THREAD_CONTEXT_MANIPULATION));
	threadManip->threadId = remoteThreadId;
	threadManip->hProcess = hProcess;
	HWND mainWindow = FindWindowA("Tiger D3D Window", nullptr);
	HMODULE ntdll = GetModuleHandleA("ntdll");
	MODULEINFO modinfo;
	GetModuleInformation(GetCurrentProcess(), ntdll, &modinfo, sizeof(modinfo));
	int size = modinfo.SizeOfImage;

	threadManip->jmp0GadgetAddr = (DWORD64)memmem(((BYTE*)ntdll) + 0x1000, size - 0x1000, JMP_0_OPCODE, 2);
	threadManip->writeGadgetAddr = (DWORD64)memmem(((BYTE*)ntdll) + 0x1000, size - 0x1000, MOV_PTRRDX_RAX_RET, 4);
	io::log("jmp0GadgetAddr: {0:#x}", threadManip->jmp0GadgetAddr);
	io::log("writeGadgetAddr: {0:#x}", threadManip->writeGadgetAddr);

	if (!threadManip->jmp0GadgetAddr || !threadManip->writeGadgetAddr)
	{
		io::log("Failure, could not found necessary gadget!");
		return FALSE;
	}

	//Open Thread
	threadManip->hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, remoteThreadId); //THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
																			 

																				 
																				 //suspend so we can do our thing
	SuspendThread(threadManip->hThread);

	threadManip->savedThreadContext.ContextFlags = CONTEXT_FULL;

	GetThreadContext(threadManip->hThread, &(threadManip->savedThreadContext));
	io::log("   [-] Modify context to point to JMP 0\n");
	PostMessage(mainWindow, WM_USER, 0, 0);
	PostMessage(mainWindow, WM_USER, 0, 0);
	PostMessage(mainWindow, WM_USER, 0, 0);

	//Sex context
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(threadManip->hThread, &threadContext);
	threadContext.Rip = (ULONG_PTR)threadManip->jmp0GadgetAddr;
	SetThreadContext(threadManip->hThread, &threadContext);


	//wait till rip is correct
	do
	{
		ResumeThread(threadManip->hThread);
		Sleep(50);
		SuspendThread(threadManip->hThread);
		GetThreadContext(threadManip->hThread, &threadContext);
	} while (threadContext.Rip != threadManip->jmp0GadgetAddr);

	if (threadManip->hThread != NULL) {
		threadManip->jmp0StackAddr = threadManip->savedThreadContext.Rsp - 0x8000; // leave some space for thread stack
		
		io::log("   [-] Put JMP_0 gadget addr on thread stack \n");
		//WriteToRemoteThread(threadManip, threadManip->jmp0StackAddr, threadManip->jmp0GadgetAddr);


		CONTEXT threadContext;
		threadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(threadManip->hThread, &threadContext);

		threadContext.Rax = (ULONG_PTR)threadManip->jmp0GadgetAddr;
		threadContext.Rdx = (ULONG_PTR)threadManip->jmp0StackAddr;
		threadContext.Rip = (ULONG_PTR)threadManip->writeGadgetAddr; // Gadget is: MOV [RDX], RAX; RET
		threadContext.Rsp = (ULONG_PTR)threadManip->jmp0StackAddr; // So RET will return to JMP 0 infinit loop

		SetThreadContext(threadManip->hThread, &threadContext);

		ResumeThread(threadManip->hThread);

		//Call Thread
		PostThreadMessageW(remoteThreadId, WM_NULL, 0, 0);

		Sleep(2);

		SuspendThread(threadManip->hThread);

	}
	else {
		io::log_error("Failure, could not create/access remote thread\n");
		return FALSE;
	}
	return TRUE;
}

bool EndThreadManipulation(PREMOTE_THREAD_CONTEXT_MANIPULATION threadManip) {
	io::log("Thread context manipulation completed {}", GetThreadId(threadManip->hThread));

	SetThreadContext(threadManip->hThread, &(threadManip->savedThreadContext));
	ResumeThread(threadManip->hThread);

	//Close
	CloseHandle(threadManip->hThread);

	//Clean Struct
	memset(threadManip, 0, sizeof(REMOTE_THREAD_CONTEXT_MANIPULATION));
	return TRUE;
}


int GetRemoteModuleHandle(const int processId, std::string& moduleName) {
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32W);
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

	if (!Module32First(hModule, &me32)) {
		CloseHandle(hModule);
		return 0;
	}

	while (std::string(me32.szModule) != moduleName && Module32Next(hModule, &me32)) {}

	CloseHandle(hModule);

	if (std::string(me32.szModule) == moduleName)
		return (int)me32.modBaseAddr;

	return 0;
}

ULONGLONG GetRemoteModuleHandle64Aware(unsigned PID, LPCTSTR lpModuleName, bool ShortName) {

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, PID);
	if (hSnap == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32 mod = { 0, };
	mod.dwSize = sizeof(mod);

	Module32First(hSnap, &mod);
	do {
		if (ShortName) {
			if (!_stricmp(mod.szModule, lpModuleName)) {
				CloseHandle(hSnap);
				return (ULONGLONG)mod.modBaseAddr;
			}
		}
		else {
			if (!_stricmp(mod.szExePath, lpModuleName)) {
				CloseHandle(hSnap);
				return (ULONGLONG)mod.modBaseAddr;
			}
		}
	} while (Module32Next(hSnap, &mod));

	CloseHandle(hSnap);

	return 0;
}

static ULONGLONG GetRemoteProcAddress(unsigned PID, TCHAR* pDllName, char* pFuncName)
{
	ULONGLONG pFunc = GetRemoteModuleHandle64Aware(PID, pDllName, 0);
	if (!pFunc)
		return 0;

	pFunc += ((char*)GetProcAddress(GetModuleHandle(pDllName), pFuncName) - (char*)GetModuleHandle(pDllName));
	return pFunc;
}

DWORD64 TriggerFunctionInRemoteProcess(PREMOTE_THREAD_CONTEXT_MANIPULATION threadManip, CONST TCHAR* moduleName, CONST TCHAR* functionName, DWORD64 param1, DWORD64 param2, DWORD64 param3, DWORD64 param4) {
	DWORD64 result = -1;
	FARPROC remoteProc = NULL;
	HMODULE remoteModule = NULL;


	remoteModule = GetModuleHandle(moduleName);
	io::log("-> Remote module should be at {}.", fmt::ptr(remoteModule));
	remoteProc = GetProcAddress(remoteModule, functionName);
	io::log("-> Remote proc should be at {}.", fmt::ptr(&remoteProc));
	//}

	if (remoteProc) {


		CONTEXT threadContext;
		threadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(threadManip->hThread, &threadContext);


		threadContext.Rcx = (DWORD64)param1;
		threadContext.Rdx = (DWORD64)param2;
		threadContext.R8 = (DWORD64)param3;
		threadContext.R9 = (DWORD64)param4;
		threadContext.Rip = (DWORD64)remoteProc;
		threadContext.Rsp = (DWORD64)threadManip->jmp0StackAddr; // So RET will return to JMP 0 infinit loop
		io::log("-> Setting remote thread new RIP as: {0:#x}", (DWORD64)remoteProc);
		io::log("-> Remote thread new RIP: {0:#x}", threadContext.Rip);
		io::log("-> Remote thread new RCX: {0:#x}", threadContext.Rcx);
		io::log("-> Remote thread new RDX: {0:#x}", threadContext.Rdx);
		io::log("-> Remote thread new R8: {0:#x}", threadContext.R8);
		io::log("-> Remote thread new R9: {0:#x}", threadContext.R9);
		io::log("-> Remote thread new RSP: {0:#x}", threadContext.Rsp);

		//set the stuff
		SetThreadContext(threadManip->hThread, &threadContext);

		ResumeThread(threadManip->hThread);

		//Call Thread
		PostThreadMessageW(threadManip->threadId, WM_NULL, 0, 0);

		Sleep(5000);
		DWORD exitCode = 0;
		GetExitCodeThread(threadManip->hThread, &exitCode);
		if (exitCode == STILL_ACTIVE) {
			io::log("Get proc result");
			SuspendThread(threadManip->hThread);

			threadContext.ContextFlags = CONTEXT_FULL;
			GetThreadContext(threadManip->hThread, &threadContext);

			io::log("-> Remote thread RIP: {0:#x}", threadContext.Rip);
			io::log("-> Remote thread RAX: {0:#x}", threadContext.Rax);
			result = threadContext.Rax;
			ResumeThread(threadManip->hThread);

		}
		else
		{
			io::log_error("Remote thread was killed");
		}
	}
	else
	{
		io::log_error("Could not find remote proc");
	}
	return result;
}

//https://github.com/shubham0d/PE-injection/blob/9ce12fe1ec258310bd6345c0a5dfd47222fd9ef0/PE-injection.cpp#L61
BOOL patchRelocationTable(LPVOID module, LPVOID NewBase, PBYTE CodeBuffer) {
	DWORD_PTR delta = NULL;
	DWORD_PTR olddelta = NULL;
	DWORD   i = 0;
	PIMAGE_DATA_DIRECTORY datadir;
	/* Get module PE headers */
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);

	/* delta is offset of allocated memory in target process */
	delta = (DWORD_PTR)((LPBYTE)NewBase - headers->OptionalHeader.ImageBase);

	/* olddelta is offset of image in current process */
	olddelta = (DWORD_PTR)((LPBYTE)module - headers->OptionalHeader.ImageBase);

	/* Get data of .reloc section */
	datadir = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (datadir->Size > 0 && datadir->VirtualAddress > 0) {
		/* Point to first relocation block copied in temporary buffer */
		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(CodeBuffer + datadir->VirtualAddress);

		while (reloc->VirtualAddress != 0) {
			if (reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
				sizeof(WORD);
				DWORD relocDescNb = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				LPWORD relocDescList = (LPWORD)((LPBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

				/* For each descriptor */
				for (i = 0; i < relocDescNb; i++) {
					if (relocDescList[i] > 0) {
						DWORD_PTR* p = (DWORD_PTR*)(CodeBuffer + (reloc->VirtualAddress + (0x0FFF & (relocDescList[i]))));
						/* Change the offset to adapt to injected module base address */
						*p -= olddelta;
						*p += delta;
					}
				}
			}
			/* Set reloc pointer to the next relocation block */
			reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
		}
		return TRUE;
	}
	else
		return FALSE;
}



bool ghost_test(HANDLE process, DWORD thread) {
	REMOTE_THREAD_CONTEXT_MANIPULATION threadCTX;
	//Prepare ghostwriting context
	InitThreadManipulation((HANDLE)process, &threadCTX, (DWORD)thread);



	TriggerFunctionInRemoteProcess(&threadCTX, "user32.dll", "MessageBoxA", 0, 0, 0, MB_OK);

	//Fix context back
	EndThreadManipulation(&threadCTX);



	return true;
}



bool ghostwriting(HANDLE process, DWORD thread) { 
	REMOTE_THREAD_CONTEXT_MANIPULATION threadCTX;
	//Prepare ghostwriting context
	InitThreadManipulation((HANDLE)process, &threadCTX, (DWORD)thread);

	


	LPCSTR dllPath = "C:\\payload.dll";
	//LPCSTR dllPath = "C:\\Users\\dev\\Desktop\\DoorStopRelease\\DoorStopper.dll";

	if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
		io::log("[ FAILED ] DLL file does not exist.");
		system("pause");
		return EXIT_FAILURE;
	}

	HWND hwnd = FindWindowW(L"Tiger D3D Window", NULL); //Game window classname
	if (hwnd == NULL) {
		io::log("[ FAILED ] Could not find target window.");
		system("pause");
		return EXIT_FAILURE;
	}

	// Getting the thread of the window and the PID
	DWORD pid = NULL;
	DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
	if (tid == NULL) {
		io::log("[ FAILED ] Could not get thread ID of the target window.");
		system("pause");
		return EXIT_FAILURE;
	}

	if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
		io::log("[ FAILED ] DLL file does not exist.");
		system("pause");
		return EXIT_FAILURE;
	}

	// Loading DLL
	HMODULE dll = LoadLibraryEx(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES); //Loading dll from params
	if (dll == NULL) {
		io::log("[ FAILED ] The DLL could not be found.");
		system("pause");
		return EXIT_FAILURE;
	}

	// Getting exported function address
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "NextHook"); //export see dllmain.cpp "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam)
	if (addr == NULL) {
		io::log("[ FAILED ] The function was not found.");
		system("pause");
		return EXIT_FAILURE;
	}

	// Setting the hook in the hook chain
	HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, tid); // Or WH_KEYBOARD if you prefer to trigger the hook manually

	

	if (handle == NULL) {
		io::log("[ FAILED ] Couldn't set the hook with SetWindowsHookEx.");
		system("pause");
		return EXIT_FAILURE;
	}

	// Triggering the hook
	//PostThreadMessage(tid, WM_NULL, NULL, NULL);

	
	//TriggerFunctionInRemoteProcess(&threadCTX, "user32.dll", "MessageBoxA", 0, 0, 0, MB_OK);
	TriggerFunctionInRemoteProcess(&threadCTX, "user32.dll", "PostThreadMessageA", tid, WM_NULL, NULL, NULL);

	//Fix context back
	EndThreadManipulation(&threadCTX);





	// Waiting for user input to remove the hook
	io::log("[ OK ] Hook set and triggered.");
	io::log("[ >> ] Press any key to unhook (This will unload the DLL).");
	system("pause > nul");

	// Unhooking
	BOOL unhook = UnhookWindowsHookEx(handle);
	if (unhook == FALSE) {
		io::log("[ FAILED ] Could not remove the hook.");
		system("pause");
		return EXIT_FAILURE;
	}

	io::log("[ OK ] Done. Press any key to exit.");
	system("pause > nul");
	return EXIT_SUCCESS;






	
	return true;
}



int main() {

	DWORD process_id;
	const auto thread_id = GetWindowThreadProcessId(FindWindowA("Tiger D3D Window", nullptr),&process_id);
	io::log("process_id : {}", process_id);
	io::log("thread_id : {}", thread_id);

	ghostwriting((HANDLE)process_id, thread_id);
	//ghost_test((HANDLE)process_id, thread_id);
	return 0;
}

