#include "ZKHelper.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <cstdlib>
#include <cstdint>

ZKHelper::ZKHelper(const std::string& ip, uint16_t port)
    : ip_(ip), port_(port) {
}

bool ZKHelper::testPing() const {
#ifdef _WIN32
    std::string cmd = "ping -n 1 " + ip_ + " >nul 2>&1";
#else
    std::string cmd = "ping -c 1 -W 5 " + ip_ + " >/dev/null 2>&1";
#endif
    return std::system(cmd.c_str()) == 0;
}


bool ZKHelper::testTCP() const {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return false;

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port_);

#ifdef _WIN32
    IN_ADDR addr;
    if (InetPtonA(AF_INET, ip_.c_str(), &addr) != 1) {        
        #ifdef _WIN32
        closesocket(sockfd);
        WSACleanup();
        #else
        close(sockfd);
        #endif
        return false;
    }
    server.sin_addr = addr;
#else
    server.sin_addr.s_addr = inet_addr(ip_.c_str());
#endif

    bool success = connect(sockfd, (sockaddr*)&server, sizeof(server)) == 0;

#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    return success;
}

bool ZKHelper::testUDP() const {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return false;

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port_);

#ifdef _WIN32
    IN_ADDR addr;
    if (InetPtonA(AF_INET, ip_.c_str(), &addr) != 1) {
        #ifdef _WIN32
        closesocket(sockfd);
        WSACleanup();
        #else
        close(sockfd);
        #endif
        return false;
    }
    server.sin_addr = addr;
#else
    server.sin_addr.s_addr = inet_addr(ip_.c_str());
#endif

    const char* msg = "ping";
    bool success = sendto(sockfd, msg, 4, 0, (sockaddr*)&server, sizeof(server)) >= 0;

#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    return success;
}
