#pragma once 
#include "CNamedPipe.h"
#include <vector>
#include <memory>

#define PIPE_MAGIC_NUMBER (uint32_t)0x1337 
#define MAX_PACKET_SIZE 0x2000

enum PacketType : uint32_t
{
	PACKET_TYPE_INVALID = 0x0,
	PACKET_TYPE_HANDSHAKE = 0x1,
	PACKET_TYPE_INITIALIZE = 0x2,
	PACKET_TYPE_CRC_REGION = 0x3,
	PACKET_TYPE_CHECK_HEARTBEAT = 0x4,
	PACKET_TYPE_LOG = 0x5,
	PACKET_TYPE_CLOSE_REQUEST = 0x6,
	PACKET_TYPE_CLIENT_STATUS = 0x7,
};

enum PacketStatus : uint32_t
{
	PACKET_STATUS_SUCCESS = 0x0,
	PACKET_STATUS_ERROR = 0x1,
	PACKET_STATUS_MISMATCH_CRC = 0x2,
	PACKET_STATUS_MISMATCH_HEARTBEAT = 0x3,
};


enum CStatus : uint32_t
{
	CLIENT_STATUS_LOCAL_MODULE_MODIFIED = 0x1, 
	CLIENT_STATUS_EXTERN_MODULE_MODIFIED = 0x2, 
	CLIENT_STATUS_SUSPICOUS_MODULE_LOADED = 0x4, 
	CLIENT_STATUS_INVALID_RIP = 0x8, 
	CLIENT_STATUS_INVALID_VEH = 0x10, 
	CLIENT_STATUS_USE_DR = 0x20, 
	CLIENT_STATUS_DIRECT_SYSCALL = 0x40,
	CLIENT_STATUS_DYNAMIC_MEMORY = 0x80,
	CLIENT_STATUS_UNLINKED_MODULE = 0x100,
	CLIENT_STATUS_SETWINDOWSHOOKEX = 0x200, 
	CLIENT_STATUS_THREADENTRY_IS_LOADLIB = 0x400, 
	CLIENT_STATUS_MANUAL_MAP = 0x800,  
	CLIENT_STATUS_DEBUGGER_ATTACHED = 0x1000,

	CLIENT_STATUS_HEARTBEAT_MISMATCH = 0x10000, 
};

struct CPacketBase
{
	DWORD MagicNumber;
	PacketType Type;
};

struct C2S_Packet_HandShake : CPacketBase	// s와 c가 처음 연결됐을 때, c->s 패킷을 보냄 
{											// 이 이후에 s->c가 c에서 수행되는 ac 기능에 대해 필요한 정보 전송 ( crc, pid, 
	DWORD ClientProcessId;		// PID 
	DWORD ParentProcessId;		// PPID
	ULONG ProcessCookie;	// Cookie
};

struct S2C_Packet_HandShake : CPacketBase
{
	DWORD ServerProcessId;
	DWORD ParentProcessId;
	ULONG ProcessCookie;
};

struct C2S_Packet_ClientStatus : CPacketBase
{
	DWORD ClientStatus;
};

struct C2S_Packet_CrcRegion : CPacketBase
{
	ULONG_PTR nCrcRegion;
	MemInfo Regions[256];
};

struct C2S_Packet_Log : CPacketBase
{
	char contents[0x1000];
};

struct C2S_Packet_Close : CPacketBase
{
	DWORD ExitReason;
};

struct C2S_Packet_HeartBeat : CPacketBase
{
	DWORD Encryptedx2;
};

struct S2C_Packet_HeartBeat : CPacketBase
{
	DWORD Encryptedx1;
};

class CPipeManager
{
private:
	CPipeManager(const std::string& szPipeName, DWORD dwTick) : szPipeName(szPipeName), dwTick(dwTick), ClientPipe(nullptr), ServerPipe(nullptr), hPacketHandlerThread(NULL) {};
	~CPipeManager() = default;
public:
	static CPipeManager& Instance()
	{
		static CPipeManager inst("Default", 0);
		return inst;
	}
	CPipeManager(const CPipeManager&) = delete;
	CPipeManager& operator=(const CPipeManager&) = delete;
	void SetPipeProperty(std::string& pipeName, DWORD dwTick);
	bool SS_CreateOnPacketThread();
	bool SS_DestroyOnPacketThread();
	bool SS_SendPacket_HandShake(DWORD pid, DWORD ppid, ULONG_PTR cookie);
	bool SS_SendPacket_HeartBeat(DWORD Encrypted);

	bool CS_InitializePipeManager();
	bool CS_FinalizePipeManager();
	bool CS_SendPacket_HandShake(DWORD pid, DWORD ppid, ULONG_PTR cookie);
	bool CS_SendPacket_CrcRegion(DWORD nCrcRegion, std::vector<MemInfo>& Regions);
	bool CS_SendPacket_Log(LPCSTR contents);
	bool CS_SendPacket_Close(DWORD dwReason);
	bool CS_SendPacket_Status(DWORD ClientStatus);
	DWORD CS_SendPacket_HeartBeat(DWORD Encrypted);
	template <class COutPacket, class CInPacket>
	void Request(COutPacket& out, CInPacket& in);

protected:
	DWORD OnPacketHandler();
	static DWORD WINAPI _bridge(LPVOID threadParam);
	void OnProcessingPacket(CPacketBase* packet);

private:
	std::string szPipeName;
	DWORD dwTick;
	std::shared_ptr<CNamedPipe> ClientPipe; // 클라이언트의 파이프, 서버와 연결됨 
	std::shared_ptr<CNamedPipe> ServerPipe; // 서버의 파이프, 클라이언트와 연결됨 
	HANDLE hPacketHandlerThread;
};