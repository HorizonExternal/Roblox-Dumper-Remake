#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <direct.h>
#include <time.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "Shlwapi.lib")

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Credits: Blizex, Atrexus (Idea, Main code @ https://github.com/atrexus/vulkan





void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}





class Dumper { // Do not modify any sort of code in this other than strings, to prevent it from breaking.
public:
    std::wstring ProcessName = L"RobloxPlayerBeta.exe"; // Process name, Dumper is designed for roblox mainly, so i wouldnt change this since some games might have detection.
    DWORD ProcessId = 0; // This is a settable value, So do not change it unless you're hardcoding
    HANDLE Process = NULL;
    MODULEINFO ModuleInfo = { 0 };
    std::wstring OutputPath = L"."; // The output path, You can change it to your desiring
    float DecryptionFactor = 1.0f;
    bool UseTimestamp = false;

    bool Create() {
        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        std::wcout << L"loading ntdll and resolving nt..." << std::endl;
        HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!hNtdll) return false;

        auto NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
        auto NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        auto NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
        auto NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");

        if (!NtOpenProcess || !NtQuerySystemInformation || !NtClose || !NtReadVirtualMemory) {
            std::wcerr << L"NT functions failed to load thru ntdll.dll." << std::endl;
            return false;
        }

        std::wcout << L"querying system..." << std::endl;
        ULONG BufferSize = 0x10000;
        std::vector<BYTE> Buffer(BufferSize);
        NTSTATUS Status;
        do {
            Status = NtQuerySystemInformation(SystemProcessInformation, Buffer.data(), BufferSize, &BufferSize);
            if (Status == STATUS_INFO_LENGTH_MISMATCH) {
                Buffer.resize(BufferSize);
            }
            else {
                break;
            }
        } while (true);

        if (!NT_SUCCESS(Status)) {
            std::wcerr << L"sys info failed to query." << std::endl;
            return false;
        }

        auto* ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer.data();
        while (ProcessInfo->NextEntryOffset) {
            if (ProcessInfo->ImageName.Buffer && !_wcsicmp(ProcessInfo->ImageName.Buffer, ProcessName.c_str())) {
                ProcessId = (DWORD)ProcessInfo->UniqueProcessId;
                break;
            }
            ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)ProcessInfo + ProcessInfo->NextEntryOffset);
        }

        if (ProcessId == 0) {
            std::wcerr << L"proc id for roblox.exe not found ( make sure roblox is open )" << std::endl;
            return false;
        }

        std::wcout << L"found game w proc id: " << ProcessId << std::endl;

        OBJECT_ATTRIBUTES ObjectAttributes;
        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

        CLIENT_ID ClientId;
        ClientId.UniqueProcess = (HANDLE)ProcessId;
        ClientId.UniqueThread = NULL;

        std::wcout << L"trying to dump proc w ID: " << ProcessId << std::endl;
        Status = NtOpenProcess(&Process, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
        if (!NT_SUCCESS(Status)) {
            std::wcerr << L"failed to dump proc." << std::endl;
            return false;
        }

        std::wcout << L"opened proc handle." << std::endl;
        return GetModuleInfo(Process, ProcessName.c_str(), &ModuleInfo);
    }

    bool DumpToDisk() {
        std::wcout << L"saving dump..." << std::endl;
        BYTE* Buffer = (BYTE*)malloc(ModuleInfo.SizeOfImage);
        if (!Buffer) {
            std::wcerr << L"failed to allocate mem 4 dump (prolly out of size)." << std::endl;
            return false;
        }
        ZeroMemory(Buffer, ModuleInfo.SizeOfImage);

        PVOID BaseAddress = ModuleInfo.lpBaseOfDll;
        MEMORY_BASIC_INFORMATION MemoryInfo;
        if (!VirtualQueryEx(Process, BaseAddress, &MemoryInfo, sizeof(MemoryInfo))) {
            std::wcerr << L"mem region failed to query (virtualqueryex)." << std::endl;
            free(Buffer);
            return false;
        }

        HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
        auto NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
        NTSTATUS Status = NtReadVirtualMemory(Process, BaseAddress, Buffer, MemoryInfo.RegionSize, NULL);
        if (!NT_SUCCESS(Status)) {
            std::wcerr << L"ntdll failed to read proc memory." << std::endl;
            free(Buffer);
            return false;
        }

        WCHAR Path[MAX_PATH], Extension[MAX_PATH] = L".exe";
        if (wcsrchr(ProcessName.c_str(), L'.')) wcscpy_s(Extension, MAX_PATH, wcsrchr(ProcessName.c_str(), L'.'));
        if (!PathFileExistsW(OutputPath.c_str()) && !CreateDirectoryW(OutputPath.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            std::wcerr << L"failed to create output dir." << std::endl;
            free(Buffer);
            return false;
        }

        if (UseTimestamp) {
            WCHAR Timestamp[16];
            time_t t = time(NULL);
            struct tm timeinfo;
            localtime_s(&timeinfo, &t);
            wcsftime(Timestamp, sizeof(Timestamp) / sizeof(WCHAR), L"%Y-%m-%d", &timeinfo);
            swprintf(Path, MAX_PATH, L"%s\\%s_%s%s", OutputPath.c_str(), ProcessName.c_str(), Timestamp, Extension);
        }
        else {
            swprintf(Path, MAX_PATH, L"%s\\%s", OutputPath.c_str(), ProcessName.c_str());
        }

        std::wcout << L"writing proc memory to: " << Path << std::endl;
        HANDLE File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (File == INVALID_HANDLE_VALUE) {
            std::wcerr << L"failed to create file (prolly antivirus)." << std::endl;
            free(Buffer);
            return false;
        }

        DWORD BytesWritten;
        bool result = WriteFile(File, Buffer, (DWORD)ModuleInfo.SizeOfImage, &BytesWritten, NULL);
        CloseHandle(File);
        free(Buffer);

        if (result) {
            std::wcout << L"dumped game to: " << Path << std::endl;
        }
        else {
            std::wcerr << L"ON FOENEM DIS JUS FAILED!!! TURN OFF AV OR MAKE SURE U HAVE ENOUGH SPACE." << std::endl;
        }

        return result;
    }

    bool Destroy() {
        HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
        auto NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
        return NT_SUCCESS(NtClose(Process));
    }

private:
    bool GetModuleInfo(HANDLE Process, LPCWSTR ModuleName, MODULEINFO* ModuleInfo) {
        HMODULE Modules[1024];
        DWORD Needed;
        if (!EnumProcessModules(Process, Modules, sizeof(Modules), &Needed)) return false;
        for (DWORD i = 0; i < Needed / sizeof(HMODULE); i++) {
            WCHAR Name[MAX_PATH];
            if (GetModuleFileNameExW(Process, Modules[i], Name, MAX_PATH)) {
                if (!_wcsicmp(wcsrchr(Name, L'\\') + 1, ModuleName)) {
                    return GetModuleInformation(Process, Modules[i], ModuleInfo, sizeof(MODULEINFO));
                }
            }
        }
        return false;
    }
};

int main() {
    Dumper dumper;
    if (!dumper.Create()) { // Starts the dumper
        std::wcerr << L"dumper failed for roblox.exe" << std::endl;
        system("pause");

        return EXIT_FAILURE;
    }
    if (!dumper.DumpToDisk()) {
        std::wcerr << L"unable to process memory" << std::endl;
        system("pause");

        return EXIT_FAILURE;
    }
    dumper.Destroy(); // Please do not fuck this up as it can cause detections
    std::wcout << L"memory dumped successfuly." << std::endl;
    system("pause");
    return EXIT_SUCCESS;
}
