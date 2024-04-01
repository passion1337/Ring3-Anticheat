#pragma once 
#include <string>
#include <vector>

typedef struct _LDR_VECTOR_HANDLER_LIST {
	PSRWLOCK vehLock; // a3 == 0
	PLIST_ENTRY vehList;
	PSRWLOCK vchLock; // a3 == 1 
	PLIST_ENTRY vchList;
}LDR_VECTOR_HANDLER_LIST, * PLDR_VECTOR_HANDLER_LIST;

typedef struct _LDR_VECTOR_HANDLER_ENTRY {
	LIST_ENTRY listEntry; // 0x0
	ULONG_PTR* always1; // 0x10 point to heap
	ULONG_PTR zero;
	PVOID EncodedPtr;
}LDR_VECTOR_HANDLER_ENTRY, * PLDR_VECTOR_HANDLER_ENTRY;

typedef struct _MemInfo
{
	u64 RegionStart;
	SIZE_T RegionSize;
	DWORD PreCalculatedCrc32;

	__forceinline bool IsInModule(PVOID address) const {
		return (RegionStart <= (u64)address) && ((u64)address < RegionStart + RegionSize);
	}

	void print() {
		DbgPrintf("<Base 0x%llx, dwSize 0x%llx, Crc %x>\n", RegionStart, RegionSize, PreCalculatedCrc32);
	}
}MemInfo, *PMemInfo;

struct moduleInfo
{
	UINT_PTR moduleBase;
	ULONG imagesize;
	ULONG IatCrc32;
	std::wstring moduleName;
	std::vector<MemInfo> executableSections;

	__forceinline bool IsInModule(PVOID address) const {
		return (moduleBase <= (u64)address) && ((u64)address < moduleBase + imagesize);
	}

	void print() {
		DbgPrintf("ModuleName : %ws, <0x%016llx,0x08%x>, %x\n", moduleName.c_str(), moduleBase, imagesize, IatCrc32);
		for (auto i = 0u; i < executableSections.size(); i++) {
			printf("\texe section <0x%llx,0x%llx>, %x\n", executableSections[i].RegionStart, executableSections[i].RegionSize, executableSections[i].PreCalculatedCrc32);
		}
	}
};

using LdrLoadDll_t = decltype(&LdrLoadDll);
using LdrInitializeThunk_t = decltype(&LdrInitializeThunk);
using RtlGetFullPathName_U_t = decltype(&RtlGetFullPathName_U);

namespace Global
{
	extern ULONG ClientCookie;
	extern ULONG ServerCookie;
	extern ULONG ClientProcessId;
	extern ULONG ServerProcessId;
}