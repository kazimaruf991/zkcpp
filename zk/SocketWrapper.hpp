#pragma once

#include <vector>
#include <stdexcept>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#endif

class SocketWrapper {
public:
    explicit SocketWrapper(bool useTcp = true, int timeout = 60);
    ~SocketWrapper();

    void connect(const sockaddr_in& addr);
    void send(const std::vector<uint8_t>& data);
    std::vector<uint8_t> recv(size_t size);

    void sendTo(const std::vector<uint8_t>& data, const sockaddr_in& addr);
    std::vector<uint8_t> recvFrom(size_t size);
    int getSocket() const;
    void close();
    void setTimeout(int seconds);
    std::vector<uint8_t> recvExact(size_t size);
	bool isConnected() const;

private:
    int sockfd;
    bool isTcp;
	int socketTimeout;
};
