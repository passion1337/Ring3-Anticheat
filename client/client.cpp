#include "core.h"
#include "utils.h"
#include "CPipeManager.h"
#include <time.h>

#pragma comment(lib, "Final.lib")

DWORD GenRandom32(DWORD seed)
{
	static bool first = false;
	if (!first) { first = true; srand((unsigned int)(time(NULL)) * seed);}
	DWORD r = 0;
	for (int i = 0; i < 8; i++) {
		r <<= 8;
		r |= rand() & 0xff;
	}
	return r;
}

DWORD WINAPI testThread(LPVOID param)
{
	CPipeManager* CPipe = (CPipeManager*)param;
	CPipe->CS_SendPacket_HandShake(Global::ClientProcessId, 0, Global::ClientCookie);
	
	core::ExternModuleScan::Initialize(); 
	DWORD clientStatus = 0;
	DWORD t = 0;
	while (true)
	{
		switch (t)
		{
		// heartbeat check
		case 0: {
			DWORD HeartBeat = GenRandom32(Global::ClientCookie);
			DWORD Encrypted = HeartBeat;
			Encrypted ^= Global::ServerCookie;
			Encrypted ^= Global::ClientCookie;
			DWORD Decrypted = CPipe->CS_SendPacket_HeartBeat(Encrypted);
			Decrypted ^= Global::ServerCookie;
			if (HeartBeat != Decrypted) {
				clientStatus |= CStatus::CLIENT_STATUS_HEARTBEAT_MISMATCH;
			}
		}break;
		// local process scanning
		case 1: { 
			core::LocalModuleScan::ScanModules();
			core::LocalModuleScan::ScanMemory();
		}break;
		// external process canning
		case 2: {
			core::ExternModuleScan::ScanModules();
		}break;
		// local thread scanning
		case 3: {
			core::ThreadScan::ScanLocalThreads();
		}break;
		// debugger scan
		case 4: {
			core::misc::CheckDebugger();
			core::misc::CheckVehList();
		}break;
		default: {
			t = -1;
		}break;
		}

		if (core::AcFlags.bSetWindowsHookExDetect) clientStatus |= CStatus::CLIENT_STATUS_SETWINDOWSHOOKEX;			// SetWindowsHookEx�� DLL �ε� 
		if (core::AcFlags.bUnlinkedModuleDetect) clientStatus |= CStatus::CLIENT_STATUS_UNLINKED_MODULE;			// PEB���� Unlink �� ��� 
		if (core::AcFlags.bDynamicMemoryDetect) clientStatus |= CStatus::CLIENT_STATUS_DYNAMIC_MEMORY;				// RWX �޸� 
		if (core::AcFlags.bLoadLibraryDetect) clientStatus |= CStatus::CLIENT_STATUS_THREADENTRY_IS_LOADLIB;		// LoadLibrary ȣ�� 
		if (core::AcFlags.bDirectSyscallDetect) clientStatus |= CStatus::CLIENT_STATUS_DIRECT_SYSCALL;				// Direct Syscall ȣ��
		if (core::AcFlags.bVehDetect) clientStatus |= CStatus::CLIENT_STATUS_INVALID_VEH;							// VEH �߰�
		if (core::AcFlags.bDrRegisterDetect) clientStatus |= CStatus::CLIENT_STATUS_USE_DR;							// Debug Resigster ��� �߰� 
		if (core::AcFlags.bInvalidRipDetect) clientStatus |= CStatus::CLIENT_STATUS_INVALID_RIP;					// Non-backing rip �߰� 
		if (core::AcFlags.bSuspicousDllDetect) clientStatus |= CStatus::CLIENT_STATUS_SUSPICOUS_MODULE_LOADED;		// DLL�� VirtualProtect, NonSigned 
		if (core::AcFlags.bLocalModuleCodeModified) clientStatus |= CStatus::CLIENT_STATUS_LOCAL_MODULE_MODIFIED;	// ���� ����� �ڵ� ���� 
		if (core::AcFlags.bLocalModuleIatModified) clientStatus |= CStatus::CLIENT_STATUS_LOCAL_MODULE_MODIFIED;	// ���� ����� IAT ����
		if (core::AcFlags.bExternModuleCodeModified) clientStatus |= CStatus::CLIENT_STATUS_EXTERN_MODULE_MODIFIED;	// �ܺ� ����� �ڵ� ����
		if (core::AcFlags.bExternModuleIatModified) clientStatus |= CStatus::CLIENT_STATUS_EXTERN_MODULE_MODIFIED;	// ���� ����� IAT ���� 
		if (core::AcFlags.bManualMapDetected) clientStatus |= CStatus::CLIENT_STATUS_MANUAL_MAP;					// Manual map 
		if (core::AcFlags.bBeingDebugged) clientStatus |= CStatus::CLIENT_STATUS_DEBUGGER_ATTACHED;					// �Ϲ� Windows API�� ������ �����
		
		CPipe->CS_SendPacket_Status(clientStatus);
		t++;
		Sleep(1000);
	}

	CPipe->CS_FinalizePipeManager();
	return 0;
}

int main()
{
	SetConsoleTitleA("Client");
	core::client::Initialize();
	Global::ClientProcessId = GetCurrentProcessId();
	Global::ClientCookie = Rtl::GetProcessCookie();
	
	auto& CPipe = CPipeManager::Instance();
	CPipe.SetPipeProperty(std::string("test"), 100);

	if (!CPipe.CS_InitializePipeManager()) {
		return 0;
	}
	
	DWORD Tid = 0;
	HANDLE hThread = CreateThread(0, 0, testThread, &CPipe, 0, &Tid);
	printf("Create thread : %d\n", Tid);
	WaitForSingleObject(hThread, INFINITE);
}