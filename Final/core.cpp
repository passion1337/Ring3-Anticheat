#include "core.h"
#include "utils.h"
#include <TlHelp32.h>
#include <Psapi.h>

struct unkStruct
{
	UNICODE_STRING dllPath;
	char pad[0x10];
	DWORD Flag;
};

struct DbgBuffer
{
	DWORD pid;
	char data[4096 - sizeof(DWORD)];
};

static const wchar_t* BlackListWindows[] = { L"Cheat Engine", L"Process Hacker",L"Memory Scan Options", L"Active memory only" };
static const wchar_t* BlackListProcess[] = { L"CheatEngine", L"cheat engine", L"injector", L"Xenos", L"hackmacro" };
static const wchar_t* BlackListDLL[] = { L"vehdebug-x86_64.dll" };
static const char* BlackListStrings[] = { "Lua thread terminated" };
static const char* BlackListDriver[] = { "dbk64.sys", "BlackBoneDrv10.sys" };


static BOOL CALLBACK wndProc2(HWND hWnd, LPARAM lparam);
static BOOL CALLBACK wndProc(HWND hWnd, LPARAM lparam);
namespace core
{
	ThreatsFlag AcFlags;
	HANDLE hExternalProcess = 0;




	bool IsServer;
	namespace LocalModuleScan
	{
		std::vector<moduleInfo> ModuleInfos;
	}
	namespace ExternModuleScan
	{
		std::vector<moduleInfo> ModuleInfos; 
	}
	
	namespace misc
	{
		bool CheckDebugger() {
			if (utils::CheckDebugger()) {
				DbgPrintf("Process being debugged!\n");
				AcFlags.bBeingDebugged = true;
				return true;
			}
			return false;
		}

		bool isvalidRip(u64 rip) {
			bool valid = false;
			for (const auto& m : LocalModuleScan::ModuleInfos) {
				if (m.IsInModule((pv)rip)) {
					valid = true;
					break;
				}
			}
			return valid;
		}

		void MakeModuleInfo(u64 base, moduleInfo* info, PCWSTR moduleName, u64 orgBase = 0)
		{
			auto ntheader = GET_NT_HEADERS(base);
			auto sect = IMAGE_FIRST_SECTION(ntheader);
			for (auto i = 0u; i < ntheader->FileHeader.NumberOfSections; i++, sect++) {
				if (sect->Misc.VirtualSize > 0x1000 && (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
					MemInfo sectionInfo;
					sectionInfo.PreCalculatedCrc32 = utils::calcCrc32(base + sect->VirtualAddress, sect->Misc.VirtualSize);
					sectionInfo.RegionSize = sect->Misc.VirtualSize;
					sectionInfo.RegionStart = orgBase ? (orgBase + sect->VirtualAddress) : (base + sect->VirtualAddress);
					info->executableSections.push_back(sectionInfo);
				}
			}

			info->IatCrc32 = utils::calcIatCrc32(base);
			info->moduleBase = orgBase ? orgBase : base;
			info->moduleName = std::wstring(moduleName);
			info->imagesize = GET_IMAGE_SIZE(base);
			// info->print();
		}

		// return value [ 0 = Success, 1 = IAT , 2 = Code ]
		DWORD CheckCrc(u64 base, const moduleInfo* info) 
		{
			u32 iatCrc32 = utils::calcIatCrc32(base);
			if (info->IatCrc32 != iatCrc32) return 1;

			for (auto& sect : info->executableSections) {
				u64 diff = sect.RegionStart - info->moduleBase;
				u32 Crc32 = utils::calcCrc32(base + diff, sect.RegionSize);
				if (sect.PreCalculatedCrc32 != Crc32) return 2;
			}
			return 0; 
		}

		bool CheckVehList() {
			std::vector<void*> handlers;
			int cnt = Rtl::walkVehList(&handlers);
			if (cnt > 0) {
				DbgPrintf("Process has %d veh handlers.\n", cnt);
				for (auto i = 0u; i < cnt; i++) {
					DbgPrintf("VE-Handler points -> %p\n", handlers[i]);
				}
				AcFlags.bVehDetect = true;
				return true;
			}
			return false;
		}
		
		bool ScanFileWithYara(LPCSTR filePath) {
			DWORD fileSize = 0;
			PVOID base = utils::LoadFileToMemory(filePath, &fileSize);
			if (!base) return false;
			PVOID EntryPoint = pe::GetEntryPoint(base, true);
			bool foundPattern = Yara::scanMem((void*)EntryPoint, 0x100);
			utils::freeLocal(base);
			return foundPattern;
		}

		bool ScanFileWithYara(LPCWSTR filePath) {
			char szPath[MAX_PATH];
			WideCharToMultiByte(CP_ACP, 0, filePath, -1, szPath, MAX_PATH, NULL, NULL);
			return ScanFileWithYara(szPath);
		}

		static bool QuerySystemInformation(SYSTEM_INFORMATION_CLASS klass, PVOID* outBuffer)
		{
			NTSTATUS status;
			u8 tmp[100];
			ULONG dwlocalBuffer = 100;
			PVOID localBuffer = nullptr;
			ULONG returnLength = 0;
			status = NtQuerySystemInformation(klass, tmp, dwlocalBuffer, &returnLength);
			if (status != STATUS_INFO_LENGTH_MISMATCH) return false;

			dwlocalBuffer = returnLength + 0x1000; 
			localBuffer = utils::allocLocal(PAGE_READWRITE, dwlocalBuffer);
			if (!localBuffer) return 0;

			status = NtQuerySystemInformation(klass, localBuffer, dwlocalBuffer, &returnLength);
			if (!NT_SUCCESS(status)) { utils::freeLocal(localBuffer); return false; }

			*outBuffer = localBuffer;
		}

		bool CheckModuleIsUnlinked(PVOID ModuleBase)
		{
			PTEB teb = (PTEB)__readgsqword(0x30);
			PPEB peb = teb->ProcessEnvironmentBlock;
			PLIST_ENTRY moduleList = &peb->Ldr->InLoadOrderModuleList;
			PLIST_ENTRY entry = moduleList->Flink;
			while (entry != moduleList) {
				PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (moduleEntry->DllBase == ModuleBase) return false;
				entry = entry->Flink;
			}
			return true;
		}
	}
	namespace LocalModuleScan
	{
		// 로컬 모듈 초기화 
		bool Initialize() {
			PTEB teb = (PTEB)__readgsqword(0x30);
			PPEB peb = teb->ProcessEnvironmentBlock;
			PLIST_ENTRY moduleList = &peb->Ldr->InLoadOrderModuleList;
			PLIST_ENTRY entry = moduleList->Flink;

			while (entry != moduleList) {
				moduleInfo info;
				PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				u64 base = (u64)moduleEntry->DllBase;
				misc::MakeModuleInfo(base, &info, moduleEntry->BaseDllName.Buffer);
				ModuleInfos.push_back(info);
				entry = entry->Flink;
			}
			return true;
		}
		// 모듈리스트에 정보 삽입
		void AddModuleInfo(u64 base, PCWSTR moduleName) {
			moduleInfo info;
			misc::MakeModuleInfo(base, &info, moduleName);
			ModuleInfos.push_back(info);
		}
		// 로컬 모듈 스캐닝 ( CRC )
		bool ScanModules()
		{
			for (const auto& mod : ModuleInfos) {
				DWORD crcStatus = misc::CheckCrc(mod.moduleBase, &mod);
				if (crcStatus != STATUS_SUCCESS) {
					if (crcStatus == 1) {
						DbgPrintf("%ws iat modified\n", mod.moduleName.c_str());
						AcFlags.bLocalModuleIatModified = true;
					}
					if (crcStatus == 2) {
						DbgPrintf("%ws code modified\n", mod.moduleName.c_str());
						AcFlags.bLocalModuleCodeModified = true;
					}
					return false;
				}
			}
			return true;
		}
		// 로컬 메모리 스캐닝 ( Unlink module, manualmap )
		bool ScanMemory()
		{
			SYSTEM_INFO si{};
			MEMORY_BASIC_INFORMATION mbi{};
			GetSystemInfo(&si);

			LPVOID address = si.lpMinimumApplicationAddress;
			while (address < si.lpMaximumApplicationAddress) {
				if (!VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) goto next;

				if (mbi.Protect == 0 || mbi.Protect & PAGE_NOACCESS || mbi.Protect & PAGE_GUARD) goto next;

				WORD sig = *(WORD*)mbi.BaseAddress;
				if (sig != IMAGE_DOS_SIGNATURE) goto next;

				if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT) {
					if (misc::CheckModuleIsUnlinked(mbi.BaseAddress)) {
						DbgPrintf("Unliked module detected at 0x%p\n", mbi.BaseAddress);
						AcFlags.bUnlinkedModuleDetect = true;
					}
				}
				if (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT) {
					DbgPrintf("Manual mapped module detected at %p\n", mbi.BaseAddress);
					AcFlags.bManualMapDetected = true;
				}
			next:
				address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
			}
			return true;
		}
	}
	namespace ExternModuleScan
	{
		// External(client or server) 모듈 초기화
		bool Initialize() {
			if (!hExternalProcess) {
				DWORD pid = IsServer ? Global::ClientProcessId : Global::ServerProcessId;
				// DbgPrintf("Open Process : %d, %x %d\n", pid, pid, IsServer);
				hExternalProcess = utils::openProc(PROCESS_ALL_ACCESS, pid);
				if (!hExternalProcess) { DbgPrintf("Failed to openprocess, %08X\n", GetLastError()); return false; }
			}
			HMODULE hMods[128];
			char header[0x500];
			DWORD cbNeed;
			NTSTATUS status;
			SIZE_T BytesRead;
			PVOID localBuffer;
			WCHAR szPath[MAX_PATH];
			if (K32EnumProcessModules(hExternalProcess, hMods, sizeof(hMods), &cbNeed)) {
				for (UINT i = 0u; i < (cbNeed / sizeof(HMODULE)); i++) {
					K32GetModuleFileNameExW(hExternalProcess, hMods[i], szPath, MAX_PATH);
					status = NtReadVirtualMemory(hExternalProcess, hMods[i], header, 0x500, &BytesRead);
					if (!NT_SUCCESS(status)) continue;
					auto ntheader = GET_NT_HEADERS(header);
					auto imgSize = GET_IMAGE_SIZE(header);
					localBuffer = utils::allocLocal(PAGE_READWRITE, imgSize);
					if (!localBuffer) continue;
					status = NtReadVirtualMemory(hExternalProcess, hMods[i], localBuffer, imgSize, &BytesRead);
					moduleInfo info;
					misc::MakeModuleInfo((u64)localBuffer, &info, utils::GetImageNameFromSystemPath(szPath), (u64)hMods[i]);
					ModuleInfos.push_back(info);
					utils::freeLocal(localBuffer);
				};
				DbgPrintf("initialize %lld external modules.\n", ModuleInfos.size());
				return true;
			}
			return false;
		}
		// 모듈 로드시 동기화
		bool AddModuleInfo(u64 base)
		{
			char header[0x500];
			NTSTATUS status;
			SIZE_T BytesRead;
			PVOID localBuffer;
			WCHAR szPath[MAX_PATH];

			K32GetModuleFileNameExW(hExternalProcess, (HMODULE)base, szPath, MAX_PATH);
			status = NtReadVirtualMemory(hExternalProcess, (void*)base, header, 0x500, &BytesRead);
			if (!NT_SUCCESS(status)) return false;
			auto ntheader = GET_NT_HEADERS(header);
			auto imgSize = GET_IMAGE_SIZE(header);
			localBuffer = utils::allocLocal(PAGE_READWRITE, imgSize);
			if (!localBuffer)  return false;
			status = NtReadVirtualMemory(hExternalProcess,(void*)base, localBuffer, imgSize, &BytesRead);
			moduleInfo info;
			misc::MakeModuleInfo((u64)localBuffer, &info, utils::GetImageNameFromSystemPath(szPath), (u64)base);
			ModuleInfos.push_back(info);
			utils::freeLocal(localBuffer);
			return true;
		} 
		// CRC 체크 
		bool ScanModules() {
			NTSTATUS status;
			SIZE_T BytesRead;
			PVOID localBuffer;
			for (const auto& mod : ModuleInfos)
			{
				localBuffer = utils::allocLocal(PAGE_READWRITE, mod.imagesize);
				if (!localBuffer) continue;

				status = NtReadVirtualMemory(hExternalProcess, (void*)mod.moduleBase, localBuffer, mod.imagesize, &BytesRead);
				if (!NT_SUCCESS(status)) continue;

				DWORD crcStatus = misc::CheckCrc((u64)localBuffer, &mod);
				if (crcStatus != STATUS_SUCCESS) {
					if (crcStatus == 1) {
						DbgPrintf("%ws iat modified\n", mod.moduleName.c_str());
						AcFlags.bExternModuleIatModified = true;
					}
					if (crcStatus == 2) {
						DbgPrintf("%ws code modified\n", mod.moduleName.c_str());
						AcFlags.bExternModuleCodeModified = true;
					}
					utils::freeLocal(localBuffer);
					return false;
				}
				utils::freeLocal(localBuffer);
			}
			return true;
		}
	}
	namespace ThreadScan
	{
		// 로컬 스레드를 스캔해서 RIP, DR를 체크합니다.
		bool ScanLocalThreads()
		{
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, utils::getCurPID());
			if (hSnap) {
				THREADENTRY32 te32;
				te32.dwSize = sizeof(te32);
				if (Thread32First(hSnap, &te32)) {
					do {
						if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
							CONTEXT ctx{};
							ctx.ContextFlags = CONTEXT_ALL;
							HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, 0, te32.th32ThreadID);
							if (hThread) {
								if (GetThreadContext(hThread, &ctx)) {
									if (!misc::isvalidRip(ctx.Rip)) {
										DbgPrintf("Detect invalid rip :%llx at tid %d\n", ctx.Rip, te32.th32ThreadID);
										AcFlags.bInvalidRipDetect = true;
									}
									if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7) {
										DbgPrintf("Detect thread that has dr value at tid %d\n", te32.th32ThreadID);
										ctx.Dr0 = ctx.Dr1 = ctx.Dr3 = 0; 
										ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
										SetThreadContext(hThread, &ctx);
										AcFlags.bDrRegisterDetect = true;
									}
								}
								CloseHandle(hThread);
							}
						}
					} while (Thread32Next(hSnap, &te32));
				}
				CloseHandle(hSnap);
			}
			return true;
		}
	}
	namespace Hook
	{
		namespace nirvana
		{
			PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
			volatile bool IsHandleSyscall;
			extern "C" void instrumentation();
			extern "C" LPVOID KiUserExceptionDispatcher = nullptr;
			MemInfo mNtdll;
			MemInfo mWin32u;
			extern "C" void CallbackRoutine(PCONTEXT ctx)
			{
				ctx->Rip = __readgsqword(0x02d8);
				ctx->Rsp = __readgsqword(0x02e0);
				ctx->Rcx = ctx->R10;

				if (IsHandleSyscall) ZwContinue(ctx, 0);

				IsHandleSyscall = true;
				{
					PVOID KernelReturnAddress = (PVOID)ctx->Rip; // must belong Nt or win32u
					PVOID UserReturnAddress = *(PVOID*)ctx->Rsp; // must belong kernelbase, user32
					// printf("%p , %p\n", KernelReturnAddress, UserReturnAddress);
					if (!mNtdll.IsInModule(KernelReturnAddress) && !mWin32u.IsInModule(KernelReturnAddress))
					{	// direct syscall
						// todo : parsing syscall number
						DbgPrintf("Direct syscall detected at %p\n", KernelReturnAddress);
						AcFlags.bDirectSyscallDetect = true;
					}
				}
				IsHandleSyscall = false;

				ZwContinue(ctx, 0);
			}

			bool EnableHook()
			{
				u64 base = utils::GetModuleBaseAddressW(L"ntdll.dll");
				mNtdll.RegionStart = base;
				mNtdll.RegionSize = GET_IMAGE_SIZE(base);
				mNtdll.PreCalculatedCrc32 = 0;

				base = utils::GetModuleBaseAddressW(L"win32u.dll");
				mWin32u.RegionStart = base;
				mWin32u.RegionSize = GET_IMAGE_SIZE(base);
				mWin32u.PreCalculatedCrc32 = 0;

				DbgPrintf("Ntdll <0x%llx,%08llx>, win32u <0x%llx,%08llx>\n",
					mNtdll.RegionStart, mNtdll.RegionSize, mWin32u.RegionStart, mWin32u.RegionSize);

				IsHandleSyscall = false;
				memset(&info, 0, sizeof(info));
				KiUserExceptionDispatcher = utils::GetProcAddress(utils::GetModuleBaseAddressW(L"ntdll.dll"), "KiUserExceptionDispatcher");
				if (!KiUserExceptionDispatcher) return false;

				info.Version = 0;
				info.Reserved = 0;
				info.Callback = instrumentation;

				NTSTATUS status = NtSetInformationProcess(CurrentProcess, ProcessInstrumentationCallback, &info, sizeof(info));
				return NT_SUCCESS(status);
			}

			void DisableHook()
			{
				info.Version = 0;
				info.Reserved = 0;
				info.Callback = 0;
				NtSetInformationProcess(CurrentProcess, ProcessInstrumentationCallback, &info, sizeof(info));

			}
		}

		volatile bool NeedCheck = false;
		LdrLoadDll_t oLdrLoadDll = nullptr;
		RtlGetFullPathName_U_t oRtlGetFullPathName_U = nullptr;
		LdrInitializeThunk_t oLdrInitializeThunk = nullptr;
		PVOID oLdrpProcessWork = nullptr;
		PVOID oLdrpSearchPath = nullptr;

		NTSTATUS NTAPI hkLdrLoadDll(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
		{
			DbgPrintf("%ws\n", DllName->Buffer);
			PVOID frames[4]{};
			ULONG hash;
			WORD cnt = RtlCaptureStackBackTrace(0, 4, frames, &hash);
			for (auto i = 0u; i < cnt; i++) {
				u64 base, size;
				base = utils::GetModuleBaseAddressW(L"user32.dll");
				if (base) size = GET_IMAGE_SIZE(base);
				if (base && size && (base < (u64)frames[i] && (u64)frames[i] < base + size)) {
					DbgPrintf("%ws SetWindowsHookEx Detected, %p\n", DllName->Buffer, frames[i]);
					AcFlags.bSetWindowsHookExDetect = true;
					// break;
					return STATUS_DLL_NOT_FOUND;
				}
			}
			return oLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
		}
		void NTAPI hkLdrInitializeThunk(PCONTEXT ContextRecord, PVOID Parameter)
		{
			auto GetThreadStartAddress = [&]() -> PVOID {
				return (PVOID)ContextRecord->Rcx;
				/*
				PVOID StartAddy = 0;
				NtQueryInformationThread(CurrentThread, ThreadQuerySetWin32StartAddress, &StartAddy, sizeof(StartAddy), NULL);
				return StartAddy;
				*/
			};

			PVOID address = GetThreadStartAddress();
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
				if (mbi.Type & MEM_PRIVATE) {
					DbgPrintf("Dynamic memory detected : 0x%p\n", address);
					AcFlags.bDynamicMemoryDetect = true;
				}
			}

			if (address == LoadLibraryA) {
				DbgPrintf("LoadLibraryA thread detected with %s\n", (LPCWSTR)ContextRecord->Rdx);
				AcFlags.bLoadLibraryDetect = true;
			}
			if (address == LoadLibraryW) {
				DbgPrintf("LoadLibraryW thread detected with %ws\n", (LPCWSTR)ContextRecord->Rdx);
				AcFlags.bLoadLibraryDetect = true;
			}
			return oLdrInitializeThunk(ContextRecord, Parameter);
		}
		ULONG NTAPI hkRtlGetFullPathName_U(PCWSTR FullName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart)
		{
			UINT pos;
			for (pos = wcslen(FullName) - 1; FullName[pos] != L'\\'; pos--);
			u64 base = utils::GetModuleBaseAddressW(FullName + pos + 1);
			if (base) {	
				LPCWSTR dllName = utils::GetImageNameFromSystemPath(FullName);
				LocalModuleScan::AddModuleInfo(base, dllName);
				DbgPrintf("New moduled loaded - %ws\n", FullName);
				bool bHasFunc = pe::IatHasSpecificFunction((PVOID)base, "VirtualProtect");
				bool bSigned = pe::IsFileSigned(FullName);
				if (bHasFunc || !bSigned) {
					DbgPrintf("Suspicous dll(%ws) loaded, VP %d, signed %d\n", FullName + pos + 1, bHasFunc, bSigned);
					AcFlags.bSuspicousDllDetect = true;
				}
			}
			return oRtlGetFullPathName_U(FullName, BufferLength, Buffer, FilePart);
		}	
		NTSTATUS __fastcall LdrpProcessWork(unkStruct* a1, char a2)
		{
			using fn = decltype(&LdrpProcessWork);

			for (auto i = 0u; i < (sizeof(BlackListDLL) / sizeof(void*)); i++) {
				if (utils::_wcsistr(a1->dllPath.Buffer, BlackListDLL[i])) {
					DbgPrintf("Blacklist dll detected : %ws\n", a1->dllPath.Buffer);
					return STATUS_DLL_NOT_FOUND;
				}
			}

			DbgPrintf("load dll %ws with %08X\n", a1->dllPath.Buffer, a1->Flag);
			if ((a1->Flag & 0x200) == 0x200) { // fullpath 
				if (!utils::_wcsistr(a1->dllPath.Buffer, L"\\System32\\")) {
					if (GetFileAttributesW(a1->dllPath.Buffer) != -1) {
						if (!pe::IsFileSigned(a1->dllPath.Buffer)) {
							DbgPrintf("not-signed module loaded : %ws\n", a1->dllPath.Buffer);
							AcFlags.bSuspicousDllDetect;
						}
					}
				}
			}
			else
				NeedCheck = true;

			return (fn(oLdrpProcessWork))(a1, a2);
		}
		NTSTATUS __fastcall LdrpSearchPath(unkStruct* a1, __int64 a2, char a3, __int16** a4, PUNICODE_STRING a5, __int64 a6, unsigned __int16* a7, bool* a8, DWORD* a9)
		{
			using fn = decltype(&LdrpSearchPath);
			NTSTATUS result = (fn(oLdrpSearchPath)(a1, a2, a3, a4, a5, a6, a7, a8, a9));
			if (NeedCheck) { 
				NeedCheck = false;
				if (result != STATUS_DLL_NOT_FOUND) {
					if (!utils::_wcsistr(a5->Buffer, L"\\System32\\")) {
						LPCWSTR szPath = a5->Buffer + 4;
						if (!pe::IsFileSigned(szPath)) {
							DbgPrintf("not-signed module loaded : %ws\n", szPath);
							AcFlags.bSuspicousDllDetect;
						}
					}
				}
			}
			return result;
		}
		// 최상위 예외 핸들러, VEH 감지
		static void TopExceptionHandler(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
		{
			if (Context->Dr0 || Context->Dr1 || Context->Dr2 || Context->Dr3 || Context->Dr7) {
				DbgPrintf("Dr register detected at Thread %d\n", GetCurrentThreadId());
				AcFlags.bDrRegisterDetect = true;
				AcFlags.bVehDetect = misc::CheckVehList();
			}
		}
		bool Initialize() {
			u64 ntdll = utils::GetModuleBaseAddressW(L"ntdll.dll");
			auto detoursInit = [&]() -> bool {
				oLdrLoadDll = (LdrLoadDll_t)utils::GetProcAddress(ntdll, "LdrLoadDll");
				oLdrInitializeThunk = (LdrInitializeThunk_t)utils::GetProcAddress(ntdll, "LdrInitializeThunk");
				oRtlGetFullPathName_U = (RtlGetFullPathName_U_t)utils::GetProcAddress(ntdll, "RtlGetFullPathName_U");
				oLdrpSearchPath = (PVOID)RVA((ntdll + 0x5F6E1), 5);
				oLdrpProcessWork = (PVOID)RVA((ntdll + 0x1FB4E), 5);
				bool b1 = utils::redirect(true, (void**)&oLdrLoadDll, hkLdrLoadDll);
				bool b2 = utils::redirect(true, (void**)&oLdrInitializeThunk, hkLdrInitializeThunk);
				bool b3 = true; // utils::redirect(true, (void**)&oRtlGetFullPathName_U, hkRtlGetFullPathName_U);
				bool b4 = utils::redirect(true, (void**)&oLdrpSearchPath, LdrpSearchPath);
				bool b5 = utils::redirect(true, (void**)&oLdrpProcessWork, LdrpProcessWork);
				return b1 && b2 && b3 && b4 && b5;
			};

			auto exceptionHookInit = [&](PVOID hookFunction) -> bool {
				DWORD* KiUserExceptionDispatcher = (DWORD*)utils::GetProcAddress(ntdll, "KiUserExceptionDispatcher");
				if (!KiUserExceptionDispatcher) return false;
				uintptr_t* dataPtr = (uintptr_t*)((u64)KiUserExceptionDispatcher + KiUserExceptionDispatcher[1] + 8);
				DWORD oldProt;
				VirtualProtect(dataPtr, 8, PAGE_EXECUTE_READWRITE, &oldProt);
				*dataPtr = (u64)hookFunction;
				VirtualProtect(dataPtr, 8, oldProt, &oldProt);
				return true;
			};

			bool b1 = detoursInit();
			if (!b1) {
				DbgPrintf("failed to init detours.\n");
				return false;
			}
			DbgPrintf("Normal detour : %d\n", b1);
			bool b2 = exceptionHookInit(TopExceptionHandler);
			if (!b2) {
				DbgPrintf("failed to init exception handler.\n");
				return false;
			}
			DbgPrintf("Exception watcher : %d\n", b2);
			bool b3 = nirvana::EnableHook();
			DbgPrintf("Nirvana hook : %d\n", b3);
			return b1 && b2 && b3;
		}
	}

	// [Server-Only] 프로세스와 드라이버를 스캔 
	namespace SystemProcessScan
	{
		// Scan WIndows 
		void ScanWindows()
		{
			EnumWindows(wndProc, 0);
		}
		// Scan Process Name
		bool ScanMaliciousProcess()
		{
			bool find = false;
			PSYSTEM_PROCESS_INFORMATION procInfo = nullptr;
			bool result = misc::QuerySystemInformation(SystemProcessInformation, (void**)&procInfo);
			PSYSTEM_PROCESS_INFORMATION currProc = procInfo;
			if (result) {
				do {
					for (auto i = 0u; i < sizeof(BlackListProcess) / sizeof(void*); i++) {
						if (currProc->ImageName.Buffer && utils::_wcsistr(currProc->ImageName.Buffer, BlackListProcess[i])) {
							DbgPrintf("detect suspicious process : %ws\n", currProc->ImageName.Buffer);
							find = true;
						}
					}
					if (find) break;
					currProc = (PSYSTEM_PROCESS_INFORMATION)((u64)currProc + currProc->NextEntryOffset);
				} while (currProc->NextEntryOffset != 0);
				utils::freeLocal(procInfo);
			}
			return true;
		}
		// Scap Opend Handle 
		bool ScanOpendHandle(DWORD pidToCheck) // 이 pid는 lssas, crss가 될수도 ? 
		{
			u8 tmp[0x1000];
			NTSTATUS status;
			ULONG returnLength;
			WCHAR szLogicalPath[MAX_PATH];
			PUNICODE_STRING processName = (PUNICODE_STRING)tmp;
			PUNICODE_STRING ownerProcessName = (PUNICODE_STRING)((u64)processName + 0x500);
			PSYSTEM_HANDLE_INFORMATION handleInfo = nullptr;

			if (!misc::QuerySystemInformation(SystemHandleInformation, (void**)&handleInfo)) return false;
			
			for (auto i = 0u; i < handleInfo->NumberOfHandles; i++)
			{
				HANDLE hOwnerProcess = 0;
				HANDLE hDuplicated = 0;
				PROCESS_BASIC_INFORMATION Pbi{};
				PROCESS_BASIC_INFORMATION ownerPbi{};
				PSYSTEM_HANDLE_TABLE_ENTRY_INFO handle = &handleInfo->Handles[i];

				if (handle->UniqueProcessId == 0x4 || handle->UniqueProcessId == Global::ServerProcessId) continue;
				if (handle->ObjectTypeIndex != 0x7 || handle->GrantedAccess != 0x1fffff) continue;

				hOwnerProcess = utils::openProc(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, handle->UniqueProcessId);
				if (!hOwnerProcess) continue;

				status = NtDuplicateObject(hOwnerProcess, UlongToHandle(handle->HandleValue), CurrentProcess, &hDuplicated, 0x1478, 0, 0);
				if (!NT_SUCCESS(status)) {
					// duplicate failed even though handle is open, it's quite weird.
					DbgPrintf("weired\n");
					status = NtQueryInformationProcess(hOwnerProcess, ProcessImageFileName, ownerProcessName, 0x500, &returnLength);
					if (!NT_SUCCESS(status)) { NtClose(hOwnerProcess); continue; }
					utils::ConvertPhysicalPathToLogical(ownerProcessName->Buffer, szLogicalPath);
					if (core::misc::ScanFileWithYara(szLogicalPath)) {
						DbgPrintf("%ws(cheatengine) use obcallback.\n", szLogicalPath);
						NtClose(hOwnerProcess);
						break;
					}
					NtClose(hOwnerProcess);
					continue;
				}
				NtQueryInformationProcess(hDuplicated, ProcessImageFileName, processName, 0x500, &returnLength);
				NtQueryInformationProcess(hDuplicated, ProcessBasicInformation, &Pbi, sizeof(Pbi), &returnLength);
				NtQueryInformationProcess(hOwnerProcess, ProcessImageFileName, ownerProcessName, 0x500, &returnLength);
				NtQueryInformationProcess(hOwnerProcess, ProcessBasicInformation, &ownerPbi, sizeof(ownerPbi), &returnLength);
				if (Pbi.UniqueProcessId == (HANDLE)pidToCheck) {
					utils::ConvertPhysicalPathToLogical(ownerProcessName->Buffer, szLogicalPath);
					if (core::misc::ScanFileWithYara(szLogicalPath)) {
						DbgPrintf("%ws is cheatengine.\n", szLogicalPath);
						NtClose(hOwnerProcess);
						NtClose(hDuplicated);
						break;
					}
				}
				NtClose(hOwnerProcess);
				NtClose(hDuplicated);
			}
			utils::freeLocal(handleInfo);
		}
		// Scan Malicious Drivers with yara rules
		bool ScanMaliciousDriver()
		{
			PRTL_PROCESS_MODULES pSystemModules = nullptr;
			if (misc::QuerySystemInformation(SystemModuleInformation, (void**)&pSystemModules)) {
				for (auto i = 0u; i < pSystemModules->NumberOfModules; i++) {
					const PRTL_PROCESS_MODULE_INFORMATION SystemModule = &pSystemModules->Modules[i];
					char* sysName = (char*)(SystemModule->FullPathName + SystemModule->OffsetToFileName);
					if (utils::StartWithA((LPCSTR)SystemModule->FullPathName, SYSTEMROOT_PATH))
						continue;
					// 1. check driver name
					for (auto j = 0u; j < sizeof(BlackListDriver) / sizeof(void*); j++) {
						if (utils::_stristr(sysName, BlackListDriver[j])) {
							DbgPrintf("Malicious driver exists on system : %s\n", sysName);
							break;
						}
					}
					// 2. check driver signature
					LPCSTR driverPath = (LPCSTR)(SystemModule->FullPathName + 4);
					bool scanResult = core::misc::ScanFileWithYara(driverPath);
					if (scanResult) {
						DbgPrintf("cheatengine driver detect : %s\n", sysName);
						break;
					}
				}
				utils::freeLocal(pSystemModules);
			}
			return true;
		}
	}
	// [Server-Only] 사용자의 환경을 스캔 
	namespace SystemEnvScan
	{
		static bool bRunning = false;
		// Scan Prefetch folder
		bool PrefetchScan()
		{
			WCHAR dirPath[MAX_PATH];
			WIN32_FIND_DATAW findData{};
			HANDLE hFind = 0;

			GetSystemWindowsDirectoryW(dirPath, MAX_PATH);
			lstrcatW(dirPath, L"\\Prefetch\\*.pf");

			hFind = FindFirstFileW(dirPath, &findData);
			if (hFind) {
				do {
					for (u32 i = 0; i < sizeof(BlackListProcess) / sizeof(void*); i++) {
						if (utils::_wcsistr(findData.cFileName, BlackListProcess[i])) {
							DbgPrintf("Detect suspicous history => %ws\n", findData.cFileName);
							// FindClose(hFind);
						}
					}
				} while (FindNextFileW(hFind, &findData));
				FindClose(hFind);
			}

			return false;
		}
		// Scan Registry
		bool RegistryScan()
		{
			HKEY hKey;
			LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\CT", 0, KEY_READ, &hKey);
			if (result == ERROR_SUCCESS) {
				DbgPrintf("this user has history using cheatengine!\n");
				RegCloseKey(hKey);
				return true;
			}
			return false;
		}
		// Scan DbgPrint
		static DWORD WINAPI DebugStringScanFunction(LPVOID p)
		{
			DbgPrintf("DebugString scanner thread created\n");
			HANDLE hMutex, hBufferReadyEvent, hDataReadyEvent, hMapped, hStop;
			DbgBuffer* pMapped = nullptr;
			hMutex = hBufferReadyEvent = hDataReadyEvent = hMapped = hStop = 0;

			hStop = CreateEventW(0, 0, FALSE, L"DBWIN_MONITORING_STOP");
			hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, L"DBWinMutex");
			if (!hMutex) goto exit;

			hBufferReadyEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"DBWIN_BUFFER_READY");
			if (!hBufferReadyEvent) {
				hBufferReadyEvent = CreateEventW(0, 0, TRUE, L"DBWIN_BUFFER_READY");
				if (!hBufferReadyEvent) goto exit;
			}

			hDataReadyEvent = OpenEventW(SYNCHRONIZE, FALSE, L"DBWIN_DATA_READY");
			if (!hDataReadyEvent) {
				hDataReadyEvent = CreateEventW(0, 0, FALSE, L"DBWIN_DATA_READY");
				if (!hDataReadyEvent) goto exit;
			}

			hMapped = OpenFileMappingW(FILE_MAP_READ, FALSE, L"DBWIN_BUFFER");
			if (!hMapped) {
				hMapped = CreateFileMappingW((HANDLE)-1, NULL, PAGE_READWRITE, 0, sizeof(DbgBuffer), L"DBWIN_BUFFER");
				if (!hMapped) goto exit;
			}

			pMapped = (DbgBuffer*)MapViewOfFile(hMapped, SECTION_MAP_READ, 0, 0, 0);
			if (!pMapped) goto exit;


			HANDLE hEvts[2] = { hDataReadyEvent, hStop };
			DbgPrintf("Start monitoring...\n");
			while (bRunning) {
				DWORD ret = WaitForMultipleObjects(2, hEvts, FALSE, INFINITE);
				if (ret == WAIT_OBJECT_0) {
					for (u32 i = 0; i < sizeof(BlackListStrings) / sizeof(void*); i++) {
						if (strstr(BlackListStrings[i], pMapped->data)) {
							DbgPrintf("Cheatengine(PID:%d) detected!\n", pMapped->pid);
							SetEvent(hStop);
							bRunning = false;
						}
					}
					SetEvent(hBufferReadyEvent);
				}
				if (ret == WAIT_OBJECT_0 + 1) {
					break;
				}
			}
			
		exit:
			DbgPrintf("stop monitoring\n");
			if (hMutex) CloseHandle(hMutex);
			if (hBufferReadyEvent) CloseHandle(hBufferReadyEvent);
			if (hDataReadyEvent) CloseHandle(hDataReadyEvent);
			if (hMapped) CloseHandle(hMapped);
			if (hStop) CloseHandle(hStop);
			return 1;
		}
		bool StartDebugStringScan()
		{
			if (bRunning) return true; 
			bRunning = true;
			HANDLE hThread = CreateThread(0, 0, DebugStringScanFunction, 0, 0, 0);
			return hThread != 0;
		}
		void StopDebugStringScan()
		{
			if (!bRunning) return; 
			bRunning = false;
			HANDLE hEvt = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"DBWIN_MONITORING_STOP");
			SetEvent(hEvt);
		}
	}

	namespace client
	{
		bool Initialize()
		{
			IsServer = false;
			memset(&AcFlags, 0, sizeof(AcFlags));
			if (!Hook::Initialize()) return false;
			DbgPrintf("Hook initialized.\n");

			LocalModuleScan::Initialize();
			DbgPrintf("%lld modules initialized.\n", LocalModuleScan::ModuleInfos.size());

			return true;
		}
	}

	namespace server
	{
		bool Initialize()
		{
			IsServer = true;

			memset(&AcFlags, 0, sizeof(AcFlags));
			if (!Hook::Initialize()) return false;
			DbgPrintf("Hook initialized.\n");

			LocalModuleScan::Initialize();
			DbgPrintf("%lld modules initialized.\n", LocalModuleScan::ModuleInfos.size());

			if (Yara::initialize() != STATUS_SUCCESS) return false;
			DbgPrintf("Yara context initialized.\n");

			if (Yara::addRulesFromFile("yara.txt") != STATUS_SUCCESS) return false;
			DbgPrintf("Yara rules loaded.\n");
		}

		void Finalize()
		{
			Yara::finalize();
			DbgPrintf("finalize done.\n");
		}
	}

}

static BOOL CALLBACK wndProc2(HWND hWnd, LPARAM lparam)
{
	WCHAR _title[MAX_PATH];
	WCHAR _class[MAX_PATH];
	DWORD ProcessId, ThreadId;
	int result = GetWindowTextW(hWnd, _title, MAX_PATH);
	if (result) {
		for (int i = 0; i < (sizeof(BlackListWindows) / sizeof(void*)); i++) {
			if (!_wcsicmp(_title, BlackListWindows[i])) {
				GetClassNameW(hWnd, _class, MAX_PATH);
				ThreadId = GetWindowThreadProcessId(hWnd, &ProcessId);
				DbgPrintf("suspicous window : %ws, PID : %d\n", _title, ProcessId);
				return FALSE;
			}
		}
	}
	return TRUE;
}

static BOOL CALLBACK wndProc(HWND hWnd, LPARAM lparam)
{
	WCHAR _title[MAX_PATH];
	WCHAR _class[MAX_PATH];
	DWORD ProcessId, ThreadId;
	int result = GetWindowTextW(hWnd, _title, MAX_PATH);
	if (result) {
		for (int i = 0; i < (sizeof(BlackListWindows) / sizeof(void*)); i++) {
			EnumChildWindows(hWnd, wndProc2, 0);
			if (!_wcsicmp(_title, BlackListWindows[i])) {
				GetClassNameW(hWnd, _class, MAX_PATH);
				ThreadId = GetWindowThreadProcessId(hWnd, &ProcessId);
				DbgPrintf("suspicous window : %ws, PID : %d\n", _title, ProcessId);
				return FALSE;
			}
		}
	}
	return TRUE;
}

