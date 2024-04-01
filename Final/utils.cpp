#include "utils.h"
#include <yara.h>
#include <WinTrust.h>
#pragma comment(lib, "libyara.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

namespace Global
{
     ULONG ClientCookie;
     ULONG ServerCookie;
     ULONG ClientProcessId;
     ULONG ServerProcessId;
}

static u32 crctable[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

namespace utils
{
    bool CheckDebugger() 
    {
        PTEB teb = (PTEB)__readgsqword(0x30);
        PPEB peb = teb->ProcessEnvironmentBlock;
        return peb->BeingDebugged;
    }

    u64 GetModuleBaseAddressW(const wchar_t* lpModuleName)
    {
        PTEB teb = (PTEB)__readgsqword(0x30);
        PPEB peb = teb->ProcessEnvironmentBlock;
        PLIST_ENTRY moduleList = &peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY entry = moduleList->Flink;

        while (entry != moduleList) {
            PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (!_wcsicmp(moduleEntry->BaseDllName.Buffer, lpModuleName)) {
                return (u64)moduleEntry->DllBase;
            }
            entry = entry->Flink;
        }

        return 0;
    }

    pv GetProcAddress(u64 baseAddress, const char* lpProcName)
    {
        auto* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
        auto* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);

        auto exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        auto* exportDir = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + exportDirRVA);

        auto* names = (DWORD*)(baseAddress + exportDir->AddressOfNames);
        auto* functions = (DWORD*)(baseAddress + exportDir->AddressOfFunctions);
        auto* nameOrdinals = (WORD*)(baseAddress + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            const char* functionName = (const char*)(baseAddress + names[i]);
            if (!_stricmp(lpProcName, functionName)) {
                return (pv)(baseAddress + functions[nameOrdinals[i]]);
            }
        }

        return nullptr;
    }

    u32 calcCrc32(pv start, u32 len)
    {
        const char* bytes = (char*)start;
        u32 crc = ~0x0;
        for (auto i = 0u; i < len; i++) {
            u8 byte = bytes[i];
            crc = (crc >> 8) ^ crctable[(crc ^ byte) & 0xff];
        }

        return (~crc);
    }

    u32 calcCrc32(u64 start, u32 len)
    {
        return calcCrc32((pv)start, len);
    }

    u32 calcIatCrc32(u64 base)
    {
        u32 crc = 0;
        auto ntheader = GET_NT_HEADERS(base);
        auto iatDir = ntheader->OptionalHeader.DataDirectory[1];
        if (!iatDir.Size) return 0;

        auto impDesc = (PIMAGE_IMPORT_DESCRIPTOR)(base + iatDir.VirtualAddress);
        while (impDesc->Name) {
            auto cnt = 0;
            auto pThunk = (ULONG_PTR*)(base + impDesc->OriginalFirstThunk);
            auto pFunc = (ULONG_PTR*)(base + impDesc->FirstThunk);
            auto crcStart = pFunc;
            if (!pThunk) pThunk = pFunc;
            for (; *pThunk; pThunk++, pFunc++)
                cnt++;
            crc += calcCrc32(crcStart, cnt * 8);
            impDesc++;
        }
        return crc;
    }

    u32 getCurPID()
    {
        PTEB teb = (PTEB)__readgsqword(0x30);
        return (u32)teb->ClientId.UniqueProcess;
    }

    wchar_t* _wcsistr(wchar_t* str, wchar_t* substr)
    {
        if (!substr) return 0;
        for (; *str; str++) {
            wchar_t* beg = str;
            wchar_t* pat = substr;

            while (*beg && *pat && towlower(*beg) == towlower(*pat)) {
                beg++;
                pat++;
            }

            if (!*pat)
                return str;

            str = beg;
        }
        return 0;
    }

    wchar_t* _wcsistr(wchar_t* str, const wchar_t* substr)
    {
        return _wcsistr(str, (wchar_t*)substr);
    }

    char* _stristr(char* str, char* substr)
    {
        if (!substr) return 0;
        for (; *str; str++) {
            char* beg = str;
            char* pat = substr;

            while (*beg && *pat && tolower(*beg) == tolower(*pat)) {
                beg++;
                pat++;
            }

            if (!*pat)
                return str;

            str = beg;
        }
        return 0;
    }

    char* _stristr(char* str, const char* substr)
    {
        return _stristr(str, (char*)substr);
    }

    bool redirect(bool enable, void** function, void* redirection) {

        if (DetourTransactionBegin() != NO_ERROR)
        {
            return false;
        }

        if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
        {
            return false;
        }

        if ((enable ? DetourAttach : DetourDetach)(function, redirection) != NO_ERROR)
        {
            return false;
        }

        if (DetourTransactionCommit() == NO_ERROR)
        {
            return true;
        }

        DetourTransactionAbort();
        return false;
    }


    PVOID allocLocal(ULONG Protect, size_t Size) {
        PVOID address = 0;
        SIZE_T regionSize = Size;
        NTSTATUS status = NtAllocateVirtualMemory(CurrentProcess, &address, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, Protect);
        if (!NT_SUCCESS(status)) return 0;
        return address;
    }

    bool freeLocal(PVOID Buffer) {
        SIZE_T Size = 0;
        NTSTATUS status = NtFreeVirtualMemory(CurrentProcess, &Buffer, &Size, MEM_RELEASE);
        return NT_SUCCESS(status);
    }

    DWORD EnumProcessesOnSystem(DWORD* ProcessId) {
        NTSTATUS status;
        u8 tmp[100];
        ULONG dwlocalBuffer = 100;
        PVOID localBuffer = nullptr;
        ULONG returnLength = 0;
        status = NtQuerySystemInformation(SystemProcessInformation, tmp, dwlocalBuffer, &returnLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH) return 0;

        localBuffer = allocLocal(PAGE_READWRITE, returnLength);
        if (!localBuffer) return 0;

        dwlocalBuffer = returnLength;
        status = NtQuerySystemInformation(SystemProcessInformation, localBuffer, dwlocalBuffer, &returnLength);
        if (!NT_SUCCESS(status)) { freeLocal(localBuffer); return 0; }

        PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)localBuffer;
        DWORD Cnt = 0;
        do {
            ProcessId[Cnt++] = (DWORD)procInfo->UniqueProcessId;
            procInfo = (PSYSTEM_PROCESS_INFORMATION)((u64)procInfo + procInfo->NextEntryOffset);
        } while (procInfo->NextEntryOffset != 0);

        freeLocal(localBuffer);
        return Cnt;
    }

    LPCWSTR GetImageNameFromSystemPath(LPCWSTR nativePath) {
        UINT i = 0;
        for (i = wcslen(nativePath); nativePath[i] != L'\\'; i--);
        return nativePath + i + 1;
    }

    LPCWSTR GetImageNameFromSystemPath(PUNICODE_STRING nativePath) {
        for (u32 offset = nativePath->Length / 2; offset > 0; offset--)
            if (nativePath->Buffer[offset] == L'\\') return &nativePath->Buffer[offset + 1];
        return 0;
    }

    HANDLE openProc(DWORD Access, DWORD ProcessId) {
        OBJECT_ATTRIBUTES			objAttr{ 0 };
        CLIENT_ID					Cid = { (HANDLE)ProcessId, 0 };
        HANDLE						hProcess;
        NTSTATUS					status;
        objAttr.Length = sizeof(objAttr);
        status = NtOpenProcess(&hProcess, Access, &objAttr, &Cid);
        if (!NT_SUCCESS(status)) { SetLastError(status); return 0; }
        return hProcess;
    }

    bool StartWithW(LPCWSTR src, LPCWSTR pat) {
        u32 len1 = wcslen(src);
        u32 len2 = wcslen(pat);
        if (len1 < len2) return false;

        return (_wcsnicmp(src, pat, len2) == 0);
    }

    bool StartWithA(LPCSTR src, LPCSTR pat) {
        u32 len1 = strlen(src);
        u32 len2 = strlen(pat);
        if (len1 < len2) return false;

        return (_strnicmp(src, pat, len2) == 0);
    }

    bool EndWithW(LPCWSTR src, LPCWSTR pat) {
        u32 len1 = wcslen(src);
        u32 len2 = wcslen(pat);
        if (len1 < len2) return false;

        return (_wcsnicmp(src + len1 - len2, pat, len2) == 0);
    }

    bool EndWithA(LPCSTR src, LPCSTR pat) {
        u32 len1 = strlen(src);
        u32 len2 = strlen(pat);
        if (len1 < len2) return false;

        return (_strnicmp(src + len1 - len2, pat, len2) == 0);
    }

    PVOID LoadFileToMemory(LPCSTR filePath, PDWORD fileSize) {
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return 0;

        DWORD size = GetFileSize(hFile, 0);
        if (size == INVALID_FILE_SIZE) { CloseHandle(hFile); return 0; }

        PVOID buffer = allocLocal(PAGE_READWRITE, size);
        if (!buffer) { CloseHandle(hFile); return 0; }

        DWORD BytesRead;
        BOOL success = ReadFile(hFile, buffer, size, &BytesRead, NULL);
        if (!success) { CloseHandle(hFile); freeLocal(buffer); return 0; }
        if (fileSize) *fileSize = size;
        CloseHandle(hFile);
        return buffer;
    }

    bool SaveFileFromMemory(LPCSTR filePath, PVOID buf, DWORD bufSize) {
        HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD bytesWritten;
        BOOL success = WriteFile(hFile, buf, bufSize, &bytesWritten, NULL);
        CloseHandle(hFile);
        return success;
    }

    void rc4_crypt(char* key, unsigned char* data, unsigned int data_len) {
        static unsigned char initial_S[256];
        static unsigned char S[256];
        static bool init = false;
        if (init == false) {
            init = true;
            unsigned int key_length = strlen(key);
            int i, j = 0, t;

            for (i = 0; i < 256; i++) {
                initial_S[i] = i;
            }
            for (i = 0; i < 256; i++) {
                j = (j + initial_S[i] + key[i % key_length]) % 256;
                t = initial_S[i];
                initial_S[i] = initial_S[j];
                initial_S[j] = t;
            }
        }

        int i = 0, j = 0, x, t;
        unsigned char k;
        memcpy(S, initial_S, 256);
        for (x = 0; x < data_len; x++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            t = S[i];
            S[i] = S[j];
            S[j] = t;
            k = S[(S[i] + S[j]) % 256];
            data[x] ^= k;
        }
    }

    // Phys = start with \\Device\\Harddiskvolume ..... 
    bool ConvertPhysicalPathToLogical(const wchar_t* PhysicalPath, wchar_t* logicalPath) {
        wchar_t deviceName[MAX_PATH];
        wchar_t drive[3] = L"A:";

        for (; drive[0] <= L'Z'; drive[0]++) {
            if (QueryDosDeviceW(drive, deviceName, MAX_PATH) != 0) {
                DWORD pathLen1 = wcslen(deviceName);
                if (!_wcsnicmp(PhysicalPath, deviceName, pathLen1)) {
                    DWORD pathLen2 = wcslen(PhysicalPath);
                    wcsncpy(logicalPath, drive, 2);
                    wcsncpy(logicalPath + 2, PhysicalPath + pathLen1, pathLen2 - pathLen1);
                    logicalPath[pathLen2 - pathLen1 + 2] = L'\0';
                    return true;
                }
            }
        }
        return false;
    }

}

namespace Rtl
{
    ULONG GetProcessCookie() {
        ULONG procCookie = 0;
        NtQueryInformationProcess(CurrentProcess, ProcessCookie, &procCookie, 4, 0);
        return procCookie;
    }

    PVOID EncodePointer(PVOID ptr) {
        u64 uPtr = (u64)ptr;
        ULONG cookie = GetProcessCookie();
        return (PVOID)__ROR8__(uPtr ^ cookie, cookie & 0x3F);
    }

    PVOID DecodePointer(PVOID encodedPtr) {
        u64 uEncoded = (u64)encodedPtr;
        ULONG cookie = GetProcessCookie();
        uEncoded = __ROL8__(uEncoded, cookie & 0x3F);
        return (pv)(uEncoded ^= cookie);
    }

    int walkVehList(std::vector<void*>* handlers) {
        PLDR_VECTOR_HANDLER_LIST vehHandlerList = (PLDR_VECTOR_HANDLER_LIST)RVA((u64)RtlAddVectoredExceptionHandler + 0x121, 7);
        if (vehHandlerList->vehList->Flink == vehHandlerList->vehList) return 0;
        int vehCnt = 0;
        PLDR_VECTOR_HANDLER_ENTRY head = (PLDR_VECTOR_HANDLER_ENTRY)vehHandlerList->vehList;
        PLDR_VECTOR_HANDLER_ENTRY curr = (PLDR_VECTOR_HANDLER_ENTRY)head;
        do {
            if (handlers) {
                void* decoded = DecodePointer(curr->EncodedPtr);
                handlers->push_back(decoded);
            }
            vehCnt++;
            curr = (PLDR_VECTOR_HANDLER_ENTRY)curr->listEntry.Flink;
        } while (curr != head && (u64)curr != (u64)&vehHandlerList->vehList);
        return vehCnt;
    }
}

namespace Yara {
    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;

    DWORD initialize() {
        if (yr_initialize() != ERROR_SUCCESS)
            return STATUS_APP_INIT_FAILURE;
        if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
            return STATUS_APP_INIT_FAILURE;
        return STATUS_SUCCESS;
    }

    DWORD addRulesFromFile(LPCSTR filePath, bool encByRc4) {
        DWORD size;
        u8* ruleBuffer = (u8*)utils::LoadFileToMemory(filePath, &size);
        if (!ruleBuffer)
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (yr_compiler_add_string(compiler, (const char*)ruleBuffer, nullptr) != ERROR_SUCCESS)
            return STATUS_INVALID_PARAMETER_1;
        if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
            return STATUS_INVALID_PARAMETER_2;

        utils::freeLocal(ruleBuffer);
        return STATUS_SUCCESS;
    }

    static int yaraScanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
        switch (message) {
        case CALLBACK_MSG_RULE_MATCHING: {
            YR_RULE* rule = (YR_RULE*)message_data;
            bool* foundPattern = (bool*)user_data;
            *foundPattern = true;
            return CALLBACK_ABORT; // ½ºÄµÁßÁö
        }
        }
        return CALLBACK_CONTINUE;
    }

    bool scanMem(PVOID start, u32 scanRange) {
        if (!rules) { DbgPrintf("rules must be loaded first.\n"); return false; }
        bool foundPattern = false;
        yr_rules_scan_mem(rules, (u8*)start, scanRange, 0, yaraScanCallback, &foundPattern, 0);
        return foundPattern;
    }

    void finalize() {
        yr_rules_destroy(rules);
        yr_compiler_destroy(compiler);
        yr_finalize();
    }
}

namespace pe
{
    /// <summary>
    /// convert Rva -> Raw(file) offset
    /// </summary>
    /// <param name="Rva">= Rva offset</param>
    /// <param name="file">= PE file buffer</param>
    /// <returns></returns>
    DWORD RvaToRaw(DWORD Rva, PVOID file) {
        PIMAGE_NT_HEADERS ntheader = GET_NT_HEADERS(file);
        PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntheader);
        for (unsigned int i = 0u; i < ntheader->FileHeader.NumberOfSections; i++, sect++) {
            DWORD s = sect->VirtualAddress;
            DWORD e = sect->VirtualAddress + sect->Misc.VirtualSize;
            if (s <= Rva && Rva < e) {
                DWORD diff = Rva - s;
                return sect->PointerToRawData + diff;
            }
        }
        return 0;
    }

    /// <summary>
    /// return entrypoint address
    /// </summary>
    /// <param name="base">= peImage base</param>
    /// <param name="isfile">= is file?</param>
    /// <returns></returns>
    PVOID GetEntryPoint(PVOID base, bool isfile) {
        PIMAGE_NT_HEADERS ntheader = GET_NT_HEADERS(base);
        DWORD offset = 0;
        if (isfile)
            offset = RvaToRaw(ntheader->OptionalHeader.AddressOfEntryPoint, base);
        else
            offset = ntheader->OptionalHeader.AddressOfEntryPoint;

        return ((PBYTE)base + offset);
    }

    /// <summary>
    /// return section header
    /// </summary>
    /// <param name="base">= peImage base</param>
    /// <param name="name">= section name</param>
    /// <returns></returns>
    PIMAGE_SECTION_HEADER GetSection(PVOID base, const char* name) {
        PIMAGE_NT_HEADERS ntheader = GET_NT_HEADERS(base);
        PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntheader);
        for (unsigned int i = 0u; i < ntheader->FileHeader.NumberOfSections; i++, sect++) {
            if (!_strnicmp((char*)sect->Name, name, 7)) return sect;
        }
        return nullptr;
    }

    bool IatHasSpecificFunction(PVOID base, const char* functionName) {
        auto ntheader = GET_NT_HEADERS(base);
        auto iatDir = ntheader->OptionalHeader.DataDirectory[1];
        if (!iatDir.Size) return 0;

        auto impDesc = (PIMAGE_IMPORT_DESCRIPTOR)((u64)base + iatDir.VirtualAddress);
        while (impDesc->Name) {
            auto cnt = 0;
            auto pThunk = (ULONG_PTR*)((u64)base + impDesc->OriginalFirstThunk);
            auto pFunc = (ULONG_PTR*)((u64)base + impDesc->FirstThunk);

            for (; pThunk && *pThunk; pThunk++, pFunc++) {
                if (*pThunk & IMAGE_ORDINAL_FLAG64) continue;
                auto pImpByName = (PIMAGE_IMPORT_BY_NAME)((u64)base + *pThunk);
                if(pImpByName->Name[0] && !_stricmp(pImpByName->Name, functionName))
                    return true;
            }
            impDesc++;
        }

        return false;
    }


    BOOL IsFileSigned(LPCTSTR szFileName)
    {
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        DWORD dwEncoding, dwContentType, dwFormatType;
        BOOL fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE, szFileName,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            &dwEncoding, &dwContentType, &dwFormatType,
            &hStore, &hMsg, NULL);

        if (fResult) {
            if (hStore != NULL) CertCloseStore(hStore, 0);
            if (hMsg != NULL) CryptMsgClose(hMsg);
            
            return TRUE;
        }

        return FALSE;
    }
}
