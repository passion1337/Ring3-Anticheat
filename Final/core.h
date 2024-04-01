#pragma once 
#include "native.h"
#include <string>


struct ThreatsFlag
{
	bool bSetWindowsHookExDetect;		// SetWindowsHookEx로 DLL 로드 
	bool bUnlinkedModuleDetect;			// PEB에서 Unlink 된 모듈 
	bool bDynamicMemoryDetect;			// RWX 메모리 
	bool bLoadLibraryDetect;			// LoadLibrary 호출 
	bool bDirectSyscallDetect;			// Direct Syscall 호출
	bool bVehDetect;					// VEH 발견
	bool bDrRegisterDetect;				// Debug Resigster 사용 발견 
	bool bInvalidRipDetect;				// Non-backing rip 발견 
	bool bSuspicousDllDetect;			// DLL이 VirtualProtect, NonSigned 
	bool bLocalModuleCodeModified;		// 로컬 모듈의 코드 변경 
	bool bLocalModuleIatModified;		// 로컬 모듈의 IAT 변경
	bool bExternModuleCodeModified;		// 외부 모듈의 코드 변경
	bool bExternModuleIatModified;		// 로컬 모듈의 IAT 변경 
	bool bManualMapDetected;			// Manual map 
	bool bBeingDebugged;				// 일반 Windows API로 부착된 디버거
};

namespace core
{
	extern ThreatsFlag AcFlags;
	namespace misc
	{
		bool CheckDebugger();
		bool CheckVehList();
	}
	namespace LocalModuleScan
	{
		extern std::vector<moduleInfo> ModuleInfos; // 로컬프로세스(서버)의 모듈 목록 
		bool ScanModules();
		bool ScanMemory();
	}
	namespace ExternModuleScan
	{
		extern std::vector<moduleInfo> ModuleInfos; // 클라이언트 CRC 검사 영역 
		bool Initialize();
		bool ScanModules();
	}
	namespace ThreadScan
	{
		bool ScanLocalThreads();
	}

	// [Server-Only] 프로세스와 드라이버를 스캔 
	namespace SystemProcessScan
	{
		void ScanWindows();
		bool ScanMaliciousProcess();
		bool ScanOpendHandle(DWORD pidToCheck);
		bool ScanMaliciousDriver();
	}
	// [Server-Only] 사용자의 환경을 스캔 
	namespace SystemEnvScan
	{
		bool PrefetchScan();
		bool RegistryScan();
		bool StartDebugStringScan();
		void StopDebugStringScan();
	}

	namespace client
	{
		bool Initialize();
	}

	namespace server
	{
		bool Initialize();
		void Finalize();
	}
}
