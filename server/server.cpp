#include "core.h"
#include "utils.h"
#include "CPipeManager.h"

#pragma comment(lib, "Final.lib")

DWORD WINAPI testThread(LPVOID param)
{
	while (!Global::ClientProcessId) Sleep(1000);

	DbgPrintf("Start Main Thread\n");
	CPipeManager* SPipe = (CPipeManager*)param; 
	if (!core::ExternModuleScan::Initialize()) return 0;

	// system scanning 
	core::SystemEnvScan::PrefetchScan();
	core::SystemEnvScan::RegistryScan();
	core::SystemEnvScan::StartDebugStringScan();

	DWORD t = 0;
	while (true)
	{
		switch (t)
		{
		case 0: {
			// core::SystemProcessScan::ScanWindows();
		}break;
		case 1: {
			core::SystemProcessScan::ScanMaliciousProcess();
		}break;
		case 2: {
			core::SystemProcessScan::ScanOpendHandle(Global::ClientProcessId);
		}break;
		case 3: {
			core::SystemProcessScan::ScanMaliciousDriver();
		}break;
		default: {
			t = -1;
		}break;
		}
		t++;
		Sleep(1000);
	}

	core::SystemEnvScan::StopDebugStringScan();
	core::server::Finalize();
	return 0;
}

int main() 
{

	SetConsoleTitleA("Server");
	
	if (!core::server::Initialize()) {
		return 0;
	}

	Global::ServerProcessId = GetCurrentProcessId();
	Global::ServerCookie = Rtl::GetProcessCookie();
	auto& SPipe = CPipeManager::Instance();
	SPipe.SetPipeProperty(std::string("test"), 100);
	if (!SPipe.SS_CreateOnPacketThread()) {
		return 0;
	}

	CreateThread(0, 0, testThread, &SPipe, 0, 0);
	Sleep(0xffffffff);
}