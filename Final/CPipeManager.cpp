#include "CPipeManager.h"

void CPipeManager::SetPipeProperty(std::string& pipeName, DWORD dwTick)
{
	this->szPipeName = pipeName;
	this->dwTick = dwTick;
}

bool CPipeManager::SS_CreateOnPacketThread()
{
	DWORD ThreadId = 0;
	hPacketHandlerThread = CreateThread(0, 0, _bridge, this, 0, &ThreadId);
	if (!hPacketHandlerThread) {
		DbgPrintf("Failed to create OnPacketHandler() with 0x%X\n", GetLastError());
		return false;
	}
	DbgPrintf("OnPacketHandler() ThreadId : %u\n", ThreadId);
	return true;
}

bool CPipeManager::SS_DestroyOnPacketThread()
{
	if (!hPacketHandlerThread) return false;

	TerminateThread(hPacketHandlerThread, 0);
	CloseHandle(hPacketHandlerThread);
	DbgPrintf("OnPacketHandler() terminated.\n");
	return true;
}

bool CPipeManager::SS_SendPacket_HandShake(DWORD pid, DWORD ppid, ULONG_PTR cookie)
{
	S2C_Packet_HandShake OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_HANDSHAKE;
	OutPacket.ServerProcessId = pid;
	OutPacket.ParentProcessId = ppid;
	OutPacket.ProcessCookie = cookie;

	return ServerPipe->Write(OutPacket);
}

bool CPipeManager::SS_SendPacket_HeartBeat(DWORD Encrypted)
{
	S2C_Packet_HeartBeat OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_CHECK_HEARTBEAT;
	OutPacket.Encryptedx1 = Encrypted;

	return ServerPipe->Write(OutPacket);
}

bool CPipeManager::CS_InitializePipeManager()
{
	ClientPipe = std::make_shared<CNamedPipe>(szPipeName);
	if (!ClientPipe) {
		DbgPrintf("Failed to std::make_shared<CNamedPipe>(szPipeName)\n");
		return false;
	}

	if (!ClientPipe->IsServerAvailable(500000)) {
		DbgPrintf("Server isn't available.\n");
		return false;
	}

	if (!ClientPipe->Open(GENERIC_READ | GENERIC_WRITE, 0)) {
		DbgPrintf("Failed to open namedPipe, 0x%X\n", GetLastError());
		return false;
	}

	if (!ClientPipe->SetMode(true, true)) {
		DbgPrintf("Failed to set pipe mode, 0x%X\n", GetLastError());
		return false;
	}

	DbgPrintf("ClientPipe initialized sucessfully.\n");
	return true;
}

bool CPipeManager::CS_FinalizePipeManager()
{
	if (!ClientPipe->IsOpen()) return false; // pipe is already broken.
	if (!ClientPipe->Flush()) {
		DbgPrintf("Failed to flush pipe buffer, 0x%X\n", GetLastError());
		return false;
	}
	if (!ClientPipe->Close()) {
		DbgPrintf("Failed to close pipe, 0x%X\n", GetLastError());
		return false;
	}
	ClientPipe->Detach();
	DbgPrintf("ClinePipe finalized successfully.\n");
	return true;
}

bool CPipeManager::CS_SendPacket_HandShake(DWORD pid, DWORD ppid, ULONG_PTR cookie)
{
	C2S_Packet_HandShake OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_HANDSHAKE;
	OutPacket.ClientProcessId = pid;
	OutPacket.ParentProcessId = ppid;
	OutPacket.ProcessCookie = cookie;

	S2C_Packet_HandShake InPacket;
	Request(OutPacket, InPacket);
	ClientPipe->Flush();

	// InPacket에 대한 처리 해야함 
	// 만약 create 한 server 와 pid가 일치하지 않다거나, etc...  
	Global::ServerCookie = InPacket.ProcessCookie;
	Global::ServerProcessId = InPacket.ServerProcessId;
	DbgPrintf("spid %d, serverCookie : %x\n", InPacket.ServerProcessId, InPacket.ProcessCookie);
	return true;
}

bool CPipeManager::CS_SendPacket_CrcRegion(DWORD nCrcRegion, std::vector<MemInfo>& Regions)
{
	C2S_Packet_CrcRegion OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_CRC_REGION;
	for (auto i = 0u; i < Regions.size(); i++) {
		OutPacket.Regions[i].RegionStart = Regions[i].RegionStart;
		OutPacket.Regions[i].RegionSize = Regions[i].RegionSize;
		OutPacket.Regions[i].PreCalculatedCrc32 = 0;
	}

	return ClientPipe->Write(OutPacket);
}

bool CPipeManager::CS_SendPacket_Log(LPCSTR contents)
{
	C2S_Packet_Log OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_CLOSE_REQUEST;
	RtlCopyMemory(OutPacket.contents, contents, strlen(contents) + 1);

	return ClientPipe->Write(OutPacket);
}

bool CPipeManager::CS_SendPacket_Close(DWORD ExitReason)
{
	C2S_Packet_Close  OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_CLOSE_REQUEST;
	OutPacket.ExitReason = ExitReason;

	return ClientPipe->Write(OutPacket);
}

bool CPipeManager::CS_SendPacket_Status(DWORD ClientStatus)
{
	C2S_Packet_ClientStatus OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_CLIENT_STATUS;
	OutPacket.ClientStatus = ClientStatus;

	return ClientPipe->Write(OutPacket);
}

DWORD CPipeManager::CS_SendPacket_HeartBeat(DWORD Encrypted)
{
	C2S_Packet_HeartBeat OutPacket;
	OutPacket.MagicNumber = PIPE_MAGIC_NUMBER;
	OutPacket.Type = PacketType::PACKET_TYPE_CHECK_HEARTBEAT;
	OutPacket.Encryptedx2 = Encrypted;

	S2C_Packet_HeartBeat InPacket;
	Request(OutPacket, InPacket);
	ClientPipe->Flush();
	return InPacket.Encryptedx1;
}

template <class COutPacket, class CInPacket>
void CPipeManager::Request(COutPacket& out, CInPacket& in)
{
	// send from client, to server
	if (ClientPipe) {
		ClientPipe->Write(out);
		ClientPipe->Read(in);
	}
	// send from server, to client
	else {
		ServerPipe->Write(out);
		ServerPipe->Read(in);
	}
}

DWORD CPipeManager::OnPacketHandler()
{
	ServerPipe = std::make_shared<CNamedPipe>(szPipeName);
	if (!ServerPipe) {
		DbgPrintf("Failed to alloc CNamedPipe\n");
		return 0;
	}
	if (!ServerPipe->Create(PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, MAX_PACKET_SIZE, MAX_PACKET_SIZE, 0)) {
		DbgPrintf("Failed to CreateNamedPipeA with 0x%X\n", GetLastError());
		return 0;
	}
	DbgPrintf("Create pipe %s, wait client\n", szPipeName.c_str());
	if (!ServerPipe->ConnectClient(0)) {
		DbgPrintf("Failed to connect client.\n");
		return 0;
	}
	DbgPrintf("connection has established.\n");

	try
	{
		BYTE pData[MAX_PACKET_SIZE];
		auto packet = (CPacketBase*)pData;
		while (true)
		{
			if (!ServerPipe->Read(pData))
			{
				DWORD Error = GetLastError();
				DbgPrintf("Failed to read from pipe with 0x%X\n", GetLastError());
				break;
			}
			if (packet->MagicNumber != PIPE_MAGIC_NUMBER) continue;
			// DbgPrintf("Data arrived from client, Type=%x\n", packet->Type);
			OnProcessingPacket(packet);
		}
	}
	catch (...) {
		DbgPrintf("Exception occurd.\n");
	}
}

DWORD WINAPI CPipeManager::_bridge(LPVOID threadParam)
{ // this function server only
	CPipeManager* _this = (CPipeManager*)threadParam;
	return _this->OnPacketHandler();
}

void CPipeManager::OnProcessingPacket(CPacketBase* packet)
{
	switch (packet->Type)
	{
	case PACKET_TYPE_HANDSHAKE: {
		auto req = (C2S_Packet_HandShake*)packet;
		DbgPrintf("Handshake from pid=%u, cookie=0x%X\n", req->ClientProcessId, req->ProcessCookie);
		Global::ClientCookie = req->ProcessCookie;
		Global::ClientProcessId = req->ClientProcessId;
		DbgPrintf("%X %X !\n", Global::ClientCookie, Global::ClientProcessId);
		SS_SendPacket_HandShake(Global::ServerProcessId, 0, Global::ServerCookie);
	} break;
	case PACKET_TYPE_CHECK_HEARTBEAT: {
		auto req = (C2S_Packet_HeartBeat*)packet;
		DWORD x1 = (req->Encryptedx2 ^ Global::ClientCookie);
		SS_SendPacket_HeartBeat(x1);
	} break;
	case PACKET_TYPE_CLIENT_STATUS: {
		auto req = (C2S_Packet_ClientStatus*)packet;
		if(req->ClientStatus != 0)
			DbgPrintf("Status : %08X\n", req->ClientStatus);
	} break;
	case PACKET_TYPE_CRC_REGION: {
		auto req = (C2S_Packet_CrcRegion*)packet;
		// not implemented 
	} break;
	case PACKET_TYPE_LOG: {
		auto req = (C2S_Packet_Log*)packet;
		DbgPrintf("Client >> %s\n", req->contents);
	} break;
	case PACKET_TYPE_CLOSE_REQUEST: {
		auto req = (C2S_Packet_Close*)packet;
		// not implemented
	}break;
	}

}

