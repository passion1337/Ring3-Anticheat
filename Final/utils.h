#pragma once 
#include "native.h"
#include <vector>
#include <detours/detours.h>
namespace utils
{
    bool CheckDebugger();
    u64 GetModuleBaseAddressW(const wchar_t* lpModuleName);
    pv GetProcAddress(u64 baseAddress, const char* lpProcName);
    u32 getCurPID();
    u32 calcCrc32(pv start, u32 len);
    u32 calcCrc32(u64 start, u32 len);
    u32 calcIatCrc32(u64 base);
    wchar_t* _wcsistr(wchar_t* str, wchar_t* substr);
    wchar_t* _wcsistr(wchar_t* str, const wchar_t* substr);
    char* _stristr(char* str, char* substr);
    char* _stristr(char* str, const char* substr);
    bool redirect(bool enable, void** function, void* redirection);
    PVOID allocLocal(ULONG Protect, size_t Size);
    bool freeLocal(PVOID Buffer);
    HANDLE openProc(DWORD Access, DWORD ProcessId);   
    DWORD EnumProcessesOnSystem(DWORD* ProcessId);
    bool StartWithW(LPCWSTR src, LPCWSTR pat);
    bool StartWithA(LPCSTR src, LPCSTR pat);
    bool EndWithW(LPCWSTR src, LPCWSTR pat);
    bool EndWithA(LPCSTR src, LPCSTR pat);
    PVOID LoadFileToMemory(LPCSTR filePath, PDWORD fileSize);
    bool SaveFileFromMemory(LPCSTR filePath, PVOID buf, DWORD bufSize);
    void rc4_crypt(char* key, unsigned char* data, unsigned int data_len);
    LPCWSTR GetImageNameFromSystemPath(LPCWSTR nativePath);
    LPCWSTR GetImageNameFromSystemPath(PUNICODE_STRING nativePath);
    bool ConvertPhysicalPathToLogical(const wchar_t* PhysicalPath, wchar_t* logicalPath);
}

namespace Rtl
{
    ULONG GetProcessCookie();
    PVOID EncodePointer(PVOID ptr);
    PVOID DecodePointer(PVOID encodedPtr);
    int walkVehList(std::vector<void*>* handlers = nullptr);
}

namespace Yara
{
    DWORD initialize();
    DWORD addRulesFromFile(LPCSTR filePath, bool encByRc4 = false);
    bool scanMem(PVOID start, u32 scanRange);
    void finalize();
}

namespace pe
{
    DWORD RvaToRaw(DWORD Rva, PVOID file);
    PVOID GetEntryPoint(PVOID base, bool isfile = false);
    bool IatHasSpecificFunction(PVOID base, const char* functionName);
    PIMAGE_SECTION_HEADER GetSection(PVOID base, const char* name);
    BOOL IsFileSigned(LPCTSTR szFileName);
}
