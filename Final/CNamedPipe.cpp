#include "CNamedPipe.h"

#define IS_VALID_HANDLE(handle)				(handle && handle != INVALID_HANDLE_VALUE)

CNamedPipe::CNamedPipe()
{
	m_hPipe = INVALID_HANDLE_VALUE;
	m_szPipeName = "";
}

CNamedPipe::CNamedPipe(const std::string& szPipeName)
{
	m_hPipe = INVALID_HANDLE_VALUE;
	m_szPipeName = szPipeName;
}

CNamedPipe::~CNamedPipe()
{
	DbgPrintf("CNamedPipe::~CNamedPipe\n");
	Close();
}

bool CNamedPipe::Create(DWORD dwOpenMode, DWORD dwPipeMode, DWORD dwMaxInstances, DWORD dwOutBufferSize, DWORD dwInBufferSize, DWORD dwDefaultTimeOut)
{
	if (IsOpen())
	{
		DbgPrintf("Target pipe is already opened\n");
		return false;
	}

	SECURITY_DESCRIPTOR sd = { 0 };
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, static_cast<PACL>(0), FALSE);

	SECURITY_ATTRIBUTES sa = { 0 };
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = FALSE;

	std::string szPipeName = "\\\\.\\pipe\\" + m_szPipeName;
	m_hPipe = ::CreateNamedPipeA(szPipeName.c_str(), dwOpenMode, dwPipeMode, dwMaxInstances, dwOutBufferSize, dwInBufferSize, dwDefaultTimeOut, &sa);

	if (!IS_VALID_HANDLE(m_hPipe))
	{
		DbgPrintf("CreateNamedPipeA fail! Error code: %u\n", GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::Open(DWORD dwDesiredAccess, DWORD dwShareMode)
{
	if (IsOpen())
	{
		DbgPrintf("Target pipe is already opened\n");
		return false;
	}

	auto szPipeName = "\\\\.\\pipe\\" + m_szPipeName;

	m_hPipe = CreateFileA(szPipeName.c_str(), dwDesiredAccess, dwShareMode, NULL, OPEN_EXISTING, NULL, NULL);
	if (!IS_VALID_HANDLE(m_hPipe))
	{
		DbgPrintf("CreateFileA(Open) fail! Error code: %u\n", GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::Attach(HANDLE hPipe)
{
	if (m_hPipe != hPipe)
		Close();

	m_hPipe = hPipe;
	return true;
}

HANDLE CNamedPipe::Detach()
{
	auto hReturn = m_hPipe;
	m_hPipe = INVALID_HANDLE_VALUE;
	return hReturn;
}

bool CNamedPipe::Close()
{
	bool bSuccess = false;

	if (IsOpen() == false)
		return bSuccess;

	bSuccess = CloseHandle(m_hPipe);
	if (!bSuccess)
	{
		DbgPrintf("SafeCloseHandle fail! Error: %u\n", GetLastError());
	}

	return bSuccess;
}

bool CNamedPipe::ConnectClient(LPOVERLAPPED lpOverlapped)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	BOOL bServerPipe;
	if (!IsServerPipe(bServerPipe))
	{
		DbgPrintf("Target pipe is not a server pipe\n");
		return false;
	}
	if (!bServerPipe)
	{
		DbgPrintf("Must be called from the server side\n");
		return false;
	}

	auto bSuccess = ::ConnectNamedPipe(m_hPipe, lpOverlapped) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	if (!bSuccess)
	{
		DbgPrintf("ConnectNamedPipe fail! Error code: %u\n", GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::DisconnectClient()
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	BOOL bServerPipe;
	if (!IsServerPipe(bServerPipe))
	{
		DbgPrintf("Target pipe is not a server pipe\n");
		return false;
	}
	if (!bServerPipe)
	{
		DbgPrintf("Must be called from the server side\n");
		return false;
	}

	auto bSuccess = ::DisconnectNamedPipe(m_hPipe);
	if (!bSuccess)
	{
		DbgPrintf("DisconnectNamedPipe fail! Error code: %u\n", GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::Flush()
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	auto bSuccess = ::FlushFileBuffers(m_hPipe);
	if (!bSuccess)
	{
		DbgPrintf("FlushFileBuffers fail! Error code: %u\n", GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::Write(LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	auto dwWrittenByteCount = 0UL;
	auto bSuccess = WriteFile(m_hPipe, lpBuffer, dwNumberOfBytesToWrite, &dwWrittenByteCount, NULL);
	if (!bSuccess || dwWrittenByteCount != dwNumberOfBytesToWrite)
	{
		DbgPrintf("WriteFile fail! Error code: %u\n", GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::Read(LPVOID lpBuffer, DWORD dwNumberOfBytesToRead)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	auto dwReadBytesCount = 0UL;
	auto bSuccess = ReadFile(m_hPipe, lpBuffer, dwNumberOfBytesToRead, &dwReadBytesCount, NULL);
	//	if (!bSuccess || dwReadBytesCount != dwNumberOfBytesToRead)
	if (!bSuccess)
	{
		//		DbgPrintf("ReadFile fail! Req size: %u Read size: %u Error code: %u\n", dwNumberOfBytesToRead, dwReadBytesCount,GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::Peek(LPVOID lpBuffer, DWORD dwBufferSize, DWORD& dwBytesRead, DWORD& dwTotalBytesAvail, DWORD& dwBytesLeftThisMessage)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	auto bSuccess = ::PeekNamedPipe(m_hPipe, lpBuffer, dwBufferSize, &dwBytesRead, &dwTotalBytesAvail, &dwBytesLeftThisMessage);
	if (!bSuccess) {
		DbgPrintf("Peek failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::Transact(LPVOID lpInBuffer, DWORD dwInBufferSize, LPVOID lpOutBuffer, DWORD dwOutBufferSize, DWORD& dwBytesRead)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	auto bSuccess = ::TransactNamedPipe(m_hPipe, lpInBuffer, dwInBufferSize, lpOutBuffer, dwOutBufferSize, &dwBytesRead, NULL);
	if (!bSuccess) {
		DbgPrintf("Transact failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::IsBlockingPipe(BOOL& bIsBlocking) const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	DWORD dwState;
	auto bSuccess = ::GetNamedPipeHandleStateA(m_hPipe, &dwState, NULL, NULL, NULL, NULL, 0);
	if (!bSuccess) {
		DbgPrintf("IsBlockingPipe failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}

	bIsBlocking = ((dwState & PIPE_NOWAIT) == 0);
	return true;
}

bool CNamedPipe::IsClientPipe(BOOL& bClientPipe) const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	DWORD dwFlags;
	auto bSuccess = ::GetNamedPipeInfo(m_hPipe, &dwFlags, NULL, NULL, NULL);
	if (!bSuccess) {
		DbgPrintf("IsClientPipe failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}

	bClientPipe = ((dwFlags & PIPE_CLIENT_END) != 0);
	return true;
}

bool CNamedPipe::IsServerPipe(BOOL& bServerPipe) const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	DWORD dwFlags;
	auto bSuccess = ::GetNamedPipeInfo(m_hPipe, &dwFlags, NULL, NULL, NULL);
	if (!bSuccess) {
		DbgPrintf("IsServerPipe failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}

	bServerPipe = ((dwFlags & PIPE_SERVER_END) != 0);
	return true;
}

bool CNamedPipe::IsMessagePipe(BOOL& bMessagePipe) const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	DWORD dwState;
	auto bSuccess = ::GetNamedPipeHandleStateA(m_hPipe, &dwState, NULL, NULL, NULL, NULL, 0);
	if (!bSuccess)
	{
		DbgPrintf("IsMessagePipe failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}

	bMessagePipe = ((dwState & PIPE_READMODE_MESSAGE) != 0);
	return bSuccess;
}

DWORD CNamedPipe::GetCurrentInstances() const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return 0;
	}

	DWORD dwCurInstances = 0;
	auto bSuccess = ::GetNamedPipeHandleStateA(m_hPipe, NULL, &dwCurInstances, NULL, NULL, NULL, 0);
	if (!bSuccess)
	{
		DbgPrintf("GetCurrentInstances failed, GetLastError returned %d\n\n", ::GetLastError());
		return 0;
	}

	return dwCurInstances;
}

DWORD CNamedPipe::GetMaxCollectionCount() const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return 0;
	}

	BOOL bClientPipe;
	if (!IsClientPipe(bClientPipe))
	{
		DbgPrintf("Target pipe is not a client pipe\n");
		return 0;
	}
	if (!bClientPipe)
	{
		DbgPrintf("Must be called from the client side\n");
		return 0;
	}

	DWORD dwMaxCollectionCount = 0;
	auto bSuccess = ::GetNamedPipeHandleStateA(m_hPipe, NULL, NULL, &dwMaxCollectionCount, NULL, NULL, 0);
	if (!bSuccess)
	{
		DbgPrintf("GetMaxCollectionCount failed, GetLastError returned %d\n\n", ::GetLastError());
		return 0;
	}

	return dwMaxCollectionCount;
}

DWORD CNamedPipe::GetCollectionTimeout() const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return 0;
	}

	BOOL bClientPipe;
	if (!IsClientPipe(bClientPipe))
	{
		DbgPrintf("Target pipe is not a client pipe\n");
		return 0;
	}
	if (!bClientPipe)
	{
		DbgPrintf("Must be called from the client side\n");
		return 0;
	}

	DWORD dwCollectDataTimeout = 0;
	auto bSuccess = ::GetNamedPipeHandleStateA(m_hPipe, NULL, NULL, NULL, &dwCollectDataTimeout, NULL, 0);
	if (!bSuccess) {
		DbgPrintf("GetCollectionTimeout failed, GetLastError returned %d\n\n", ::GetLastError());
		return 0;
	}

	return dwCollectDataTimeout;
}

DWORD CNamedPipe::GetOutboundBufferSize() const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return 0;
	}

	DWORD dwOutBufferSize = 0;
	auto bSuccess = ::GetNamedPipeInfo(m_hPipe, NULL, &dwOutBufferSize, NULL, NULL);
	if (!bSuccess) {
		DbgPrintf("GetOutboundBufferSize failed, GetLastError returned %d\n\n", ::GetLastError());
		return 0;
	}

	return dwOutBufferSize;
}

DWORD CNamedPipe::GetInboundBufferSize() const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return 0;
	}

	DWORD dwInBufferSize = 0;
	auto bSuccess = ::GetNamedPipeInfo(m_hPipe, NULL, NULL, &dwInBufferSize, NULL);
	if (!bSuccess)
	{
		DbgPrintf("GetInboundBufferSize failed, GetLastError returned %d\n\n", ::GetLastError());
		return 0;
	}

	return dwInBufferSize;
}

std::string CNamedPipe::GetClientUserName() const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return std::string("\n");
	}

	BOOL bServerPipe;
	if (!IsServerPipe(bServerPipe))
	{
		DbgPrintf("Target pipe is not a server pipe\n");
		return std::string("\n");
	}
	if (!bServerPipe)
	{
		DbgPrintf("Must be called from the server side\n");
		return std::string("\n");
	}

	char pszUserName[_MAX_PATH];
	auto bSuccess = ::GetNamedPipeHandleStateA(m_hPipe, NULL, NULL, NULL, NULL, pszUserName, _MAX_PATH);
	if (!bSuccess)
	{
		DbgPrintf("GetClientUserName failed, GetLastError returned %d\n\n", ::GetLastError());
		return std::string("\n");
	}

	return pszUserName;
}

DWORD CNamedPipe::GetMaxInstances() const
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return 0;
	}

	DWORD dwMaxInstances = 0;
	auto bSuccess = ::GetNamedPipeInfo(m_hPipe, NULL, NULL, NULL, &dwMaxInstances);
	if (!bSuccess)
	{
		DbgPrintf("GetMaxInstances failed, GetLastError returned %d\n\n", ::GetLastError());
		return 0;
	}
	return dwMaxInstances;
}

bool CNamedPipe::SetMode(BOOL bByteMode, BOOL bBlockingMode)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	DWORD dwMode;
	if (bByteMode)
	{
		if (bBlockingMode)
			dwMode = PIPE_READMODE_BYTE | PIPE_WAIT;
		else
			dwMode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
	}
	else
	{
		if (bBlockingMode)
			dwMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
		else
			dwMode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
	}

	auto bSuccess = ::SetNamedPipeHandleState(m_hPipe, &dwMode, NULL, NULL);
	if (!bSuccess)
	{
		DbgPrintf("SetMode failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::SetMaxCollectionCount(DWORD dwCollectionCount)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	BOOL bClientPipe;
	if (!IsClientPipe(bClientPipe))
	{
		DbgPrintf("Target pipe is not a client pipe\n");
		return false;
	}
	if (!bClientPipe)
	{
		DbgPrintf("Must be called from the client side\n");
		return false;
	}

	auto bSuccess = ::SetNamedPipeHandleState(m_hPipe, NULL, &dwCollectionCount, NULL);
	if (!bSuccess)
	{
		DbgPrintf("SetMaxCollectionCount failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}
	return true;
}

bool CNamedPipe::SetCollectionTimeout(DWORD dwDataTimeout)
{
	if (!m_hPipe)
	{
		DbgPrintf("Target pipe must be open\n");
		return false;
	}

	BOOL bClientPipe;
	if (!IsClientPipe(bClientPipe))
	{
		DbgPrintf("Target pipe is not a client pipe\n");
		return false;
	}
	if (!bClientPipe)
	{
		DbgPrintf("Must be called from the client side\n");
		return false;
	}

	auto bSuccess = ::SetNamedPipeHandleState(m_hPipe, NULL, NULL, &dwDataTimeout);
	if (!bSuccess)
	{
		DbgPrintf("SetCollectionTimeout failed, GetLastError returned %d\n\n", ::GetLastError());
		return false;
	}

	return true;
}

bool CNamedPipe::Call(LPVOID lpInBuffer, DWORD dwInBufferSize, LPVOID lpOutBuffer, DWORD dwOutBufferSize, DWORD& dwBytesRead, DWORD dwTimeOut)
{
	auto szPipeName = "\\\\.\\pipe\\" + m_szPipeName;

	auto bSuccess = ::CallNamedPipeA(szPipeName.c_str(), lpInBuffer, dwInBufferSize, lpOutBuffer, dwOutBufferSize, &dwBytesRead, dwTimeOut);
	if (!bSuccess)
	{
		DbgPrintf("CallNamedPipeA fail!, Errpr code: %u\n", GetLastError());
	}

	return bSuccess;
}

// 1000 = 1s 
bool CNamedPipe::IsServerAvailable(DWORD dwTimeOut)
{
	auto szPipeName = "\\\\.\\pipe\\" + m_szPipeName;

	
	DWORD start = GetTickCount();
	while (true) {
		if (GetTickCount() - start >= dwTimeOut) {
			DbgPrintf("WaitNamedPipeA fail!, Error code: %u\n", GetLastError());
			return false;
		}
		if (WaitNamedPipeA(szPipeName.c_str(), dwTimeOut)) {
			return true;
		}
	}
	return false;
}

