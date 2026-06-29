#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, 
    DWORD fdwReason,  
    LPVOID lpvReserved
) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        WinExec("calc.exe", SW_SHOW);
    }
    return TRUE;
}
