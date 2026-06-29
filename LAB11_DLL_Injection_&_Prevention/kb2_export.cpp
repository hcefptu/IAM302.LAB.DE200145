#include <windows.h>    
#include <shellapi.h>    

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved
) {
    return TRUE;
}

extern "C" __declspec(dllexport) void LaunchWeb() {
    ShellExecuteA(
        NULL,            
        "open",          
        "https://www.google.com", 
        NULL,              
        NULL,              
        SW_SHOW      
    );
}
