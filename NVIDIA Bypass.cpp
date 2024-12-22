#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <conio.h>

const char WidevineCDM[] = " WidevineCDM module found in browser(%S)!!!!!!!!";
const char MOVBLP01[] = { 0x40, 0xb5, 0x01 };
const char NOPS[] = { 0x90, 0x90, 0x90 };

LPVOID FindData(HANDLE hProcess, LPVOID base, SIZE_T searchSize, LPVOID data, SIZE_T size) {
    for (SIZE_T i = 0; i < searchSize; i++) {
        auto current = reinterpret_cast<LPVOID>(reinterpret_cast<char*>(base) + i);
        SIZE_T read;
        char* buffer = new char[size];
        if (ReadProcessMemory(hProcess, current, buffer, size, &read)) {
            if (memcmp(buffer, data, size) == 0) {
                return current;
            }
        }
    }
    return NULL;
}

LPVOID FindLEA(HANDLE hProcess, LPVOID base, SIZE_T searchSize, LPVOID target) {
    for (SIZE_T i = 0; i < min(searchSize, reinterpret_cast<SIZE_T>(target) - reinterpret_cast<SIZE_T>(base)); i++) {
        auto current = reinterpret_cast<LPVOID>(reinterpret_cast<SIZE_T>(base) + i);
        SIZE_T read;
        auto bufferSize = 4;
        char* buffer = new char[bufferSize];
        auto diff = reinterpret_cast<SIZE_T>(target) - reinterpret_cast<SIZE_T>(current);

        if (ReadProcessMemory(hProcess, current, buffer, bufferSize, &read)) {
            if (*reinterpret_cast<DWORD*>(buffer) == diff - bufferSize) {
                return current;
            }
        }
    }
    return NULL;
}

int main(void)
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        _tprintf(TEXT("CreateToolhelp32Snapshot (of processes)"));
        return(FALSE);
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return(FALSE);
    }
    do
    {
        if (wcscmp(pe32.szExeFile, TEXT("nvcontainer.exe")) == 0) {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess == NULL)
                continue;
            HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
            MODULEENTRY32 me32;

            hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
            if (hModuleSnap == INVALID_HANDLE_VALUE)
                continue;

            me32.dwSize = sizeof(MODULEENTRY32);

            if (!Module32First(hModuleSnap, &me32))
            {
                CloseHandle(hModuleSnap);
                continue;
            }
            do
            {
                if (wcscmp(me32.szModule, TEXT("_nvspcaps64.dll")) == 0) {
                    _tprintf(TEXT("_nvspcaps64.dll: 0x%p (0x%lx)\n"), me32.modBaseAddr, me32.modBaseSize);
                    LPVOID widevineCdm = FindData(hProcess, (LPVOID)me32.modBaseAddr, me32.modBaseSize, (LPVOID)WidevineCDM, sizeof(WidevineCDM) - 1);
                    _tprintf(TEXT("WidevineCDM:     0x%p\n"), (LPVOID)widevineCdm);
                    if (!widevineCdm)
                        break;
                    LPVOID lea = FindLEA(hProcess, (LPVOID)me32.modBaseAddr, me32.modBaseSize, widevineCdm);
                    _tprintf(TEXT("LEA:          0x%p\n"), (LPVOID)lea);
                    if (!lea)
                        break;
                    LPVOID mov = FindData(hProcess, lea, 0x128, (LPVOID)MOVBLP01, sizeof(MOVBLP01));
                    _tprintf(TEXT("MOVBLP01:     0x%p\n"), (LPVOID)mov);
                    if (!mov)
                        break;
                    DWORD oldProtect;
                    if (!VirtualProtectEx(hProcess, mov, 3, 0x40, &oldProtect))
                        break;
                    SIZE_T bytes;
                    WriteProcessMemory(hProcess, mov, NOPS, 3, &bytes);

                    VirtualProtectEx(hProcess, mov, 3, oldProtect, &oldProtect);
                    _tprintf(TEXT("Patched!\n"));
                }

            } while (Module32Next(hModuleSnap, &me32));

            CloseHandle(hModuleSnap);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    _tprintf(TEXT("Press any key to close...\n"));
    _getch();
    return 0;
}