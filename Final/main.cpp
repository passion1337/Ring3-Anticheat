// #include "core.h"
#include "CPipeManager.h"
#include "CNamedPipe.h"



int main()
{
	// if (!core::client::Initialize()) return 0;
	auto& CPipe = CPipeManager::Instance();
	CPipe.SetPipeProperty(std::string("Test"), 100);
	CPipe.CS_InitializePipeManager();
}