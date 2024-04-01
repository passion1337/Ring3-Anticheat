#pragma once 
#include "native.h"
#include <string>


struct ThreatsFlag
{
	bool bSetWindowsHookExDetect;		// SetWindowsHookEx�� DLL �ε� 
	bool bUnlinkedModuleDetect;			// PEB���� Unlink �� ��� 
	bool bDynamicMemoryDetect;			// RWX �޸� 
	bool bLoadLibraryDetect;			// LoadLibrary ȣ�� 
	bool bDirectSyscallDetect;			// Direct Syscall ȣ��
	bool bVehDetect;					// VEH �߰�
	bool bDrRegisterDetect;				// Debug Resigster ��� �߰� 
	bool bInvalidRipDetect;				// Non-backing rip �߰� 
	bool bSuspicousDllDetect;			// DLL�� VirtualProtect, NonSigned 
	bool bLocalModuleCodeModified;		// ���� ����� �ڵ� ���� 
	bool bLocalModuleIatModified;		// ���� ����� IAT ����
	bool bExternModuleCodeModified;		// �ܺ� ����� �ڵ� ����
	bool bExternModuleIatModified;		// ���� ����� IAT ���� 
	bool bManualMapDetected;			// Manual map 
	bool bBeingDebugged;				// �Ϲ� Windows API�� ������ �����
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
		extern std::vector<moduleInfo> ModuleInfos; // �������μ���(����)�� ��� ��� 
		bool ScanModules();
		bool ScanMemory();
	}
	namespace ExternModuleScan
	{
		extern std::vector<moduleInfo> ModuleInfos; // Ŭ���̾�Ʈ CRC �˻� ���� 
		bool Initialize();
		bool ScanModules();
	}
	namespace ThreadScan
	{
		bool ScanLocalThreads();
	}

	// [Server-Only] ���μ����� ����̹��� ��ĵ 
	namespace SystemProcessScan
	{
		void ScanWindows();
		bool ScanMaliciousProcess();
		bool ScanOpendHandle(DWORD pidToCheck);
		bool ScanMaliciousDriver();
	}
	// [Server-Only] ������� ȯ���� ��ĵ 
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
