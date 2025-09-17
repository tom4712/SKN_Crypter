#include <windows.h>

// --- API 함수 포인터 타입 정의 ---
typedef int(WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

// 실제 기능이 실행될 스레드 함수
DWORD WINAPI PayloadThread(LPVOID lpParam) {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        MessageBoxA_t pMessageBoxA = (MessageBoxA_t)GetProcAddress(hUser32, "MessageBoxA");
        if (pMessageBoxA) {
            pMessageBoxA(NULL, "실행이 되었습니다", "알림", MB_OK);
        }
        FreeLibrary(hUser32);
    }
    ExitThread(0);
    return 0;
}

// DLL의 진입점
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    { // <-- 여기에 여는 중괄호를 추가
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;
    } // <-- 여기에 닫는 중괄호를 추가
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}