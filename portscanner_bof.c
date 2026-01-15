#include <winsock2.h>
#include <windows.h>
#include "beacon.h"

// WinSock2 function imports
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$setsockopt(SOCKET, int, int, const char*, int);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAGetLastError(void);

// MSVCRT function imports
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$atoi(const char*);

BOOL IsAlive(SOCKET s, char *ip, DWORD port) {
    struct sockaddr_in sock;
    MSVCRT$memset(&sock, 0, sizeof(sock));
    sock.sin_family = AF_INET;
    sock.sin_port = WS2_32$htons((u_short)port);
    sock.sin_addr.s_addr = WS2_32$inet_addr(ip);

    int result = WS2_32$connect(s, (struct sockaddr*)&sock, sizeof(sock));
    if(result != 0) {
        return FALSE;
    }
    
    char message[512];
    MSVCRT$sprintf(message, "GET /index.html HTTP/2.0\r\nHost: %s:%lu\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0\r\n\r\n", ip, port);
    
    result = WS2_32$send(s, message, MSVCRT$strlen(message), 0);
    if(result > 0) {
        return TRUE;
    }
    return FALSE;
}

int InitWSAContext(WSADATA *wsa) {
    return WS2_32$WSAStartup(MAKEWORD(2, 2), wsa);
}

void SetSocketTimeout(SOCKET s, int timeout) {
    WS2_32$setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    WS2_32$setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
}

void go(char *args, int len) {
    datap parser;
    char *ip;
    char *ports;
    char portBuffer[256];
    WSADATA wsa;
    
    BeaconDataParse(&parser, args, len);
    ip = BeaconDataExtract(&parser, NULL);
    ports = BeaconDataExtract(&parser, NULL);
    
    if(ip == NULL || ports == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: portscanner <ip> <ports>\n");
        BeaconPrintf(CALLBACK_ERROR, "Example: portscanner 192.168.1.1 80,443,8080\n");
        return;
    }
    
    int result = InitWSAContext(&wsa);
    if(result != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot initialize WSA. Error %d.\n", result);
        return;
    }
    
    // Copy ports string to buffer for manipulation
    MSVCRT$strcpy(portBuffer, ports);
    char *port = portBuffer;
    char *currentPort = NULL;
    
    do {
        SOCKET s;
        
        currentPort = MSVCRT$strstr(port, ",");
        if(currentPort != NULL) {
            *currentPort = 0x00;
        }
        
        // Create a new socket for each port
        s = WS2_32$socket(AF_INET, SOCK_STREAM, 0);
        if(s == INVALID_SOCKET) {
            BeaconPrintf(CALLBACK_ERROR, "socket failed. Error: %d\n", WS2_32$WSAGetLastError());
            WS2_32$WSACleanup();
            return;
        }
        
        SetSocketTimeout(s, 1000);
        
        if(IsAlive(s, ip, MSVCRT$atoi(port))) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s:%s is open\n", ip, port);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] %s:%s is closed\n", ip, port);
        }
        
        // Close the socket after each port scan
        WS2_32$closesocket(s);
        
        if(currentPort != NULL) {
            port = currentPort + 1;
        }
    } while (currentPort != NULL);

    WS2_32$WSACleanup(); 
}
