#include<iostream>
#include <string>
#include <sstream>
#include <cstring>
#include <cerrno> 
#include "SocketWrapper.hpp"

SocketWrapper::SocketWrapper(bool useTcp, int timeout) : isTcp(useTcp) {
	socketTimeout = timeout;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
#endif

    sockfd = socket(AF_INET, useTcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw std::runtime_error("Socket creation failed");
    }
}

SocketWrapper::~SocketWrapper() {
#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    ::close(sockfd);
#endif
}

void SocketWrapper::close() {
    #ifdef _WIN32
        closesocket(sockfd);
        WSACleanup();
    #else
        ::close(sockfd);
    #endif
}

void SocketWrapper::connect(const sockaddr_in& addr) {
    if (::connect(sockfd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::runtime_error("Socket connect failed");
    }
}

void SocketWrapper::send(const std::vector<uint8_t>& data) {
    size_t sent = ::send(sockfd, reinterpret_cast<const char*>(data.data()), data.size(), 0);
    if (sent < 0) {
        throw std::runtime_error("Socket send failed");
    }
}

std::vector<uint8_t> SocketWrapper::recv(size_t size) {
    std::vector<uint8_t> buffer(size);

    int attempts = 0;
    while (attempts < 10) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = socketTimeout;
        timeout.tv_usec = 0;

        int ready = select(sockfd + 1, &readfds, nullptr, nullptr, &timeout);
        if (ready > 0) {
#ifdef _WIN32
            int received = ::recv(sockfd, reinterpret_cast<char*>(buffer.data()), static_cast<int>(size), 0);
            if (received <= 0) {
                int err = WSAGetLastError();
                throw std::runtime_error("Socket recv failed: WSA error " + std::to_string(err));
            }
#else
            ssize_t received = ::recv(sockfd, buffer.data(), size, 0);
            if (received <= 0) {
                throw std::runtime_error("Socket recv failed: " + std::string(strerror(errno)));
            }
#endif
            buffer.resize(static_cast<size_t>(received));
            return buffer;
        }

        std::cerr << "[SocketWrapper] recv() timeout, retrying (" << (attempts + 1) << "/10)\n";
        attempts++;
    }

    throw std::runtime_error("recv timeout after 10 attempts");
}


std::vector<uint8_t> SocketWrapper::recvExact(size_t size) {
    std::vector<uint8_t> buffer;
    buffer.reserve(size);

    size_t totalReceived = 0;
    int attempts = 0;

    while (totalReceived < size) {
        if (attempts >= 10) {
            throw std::runtime_error("recvExact timeout after 10 attempts");
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = socketTimeout;
        timeout.tv_usec = 0;

        int ready = select(sockfd + 1, &readfds, nullptr, nullptr, &timeout);
        if (ready <= 0) {
            std::cerr << "[SocketWrapper] recvExact() timeout, retrying (" << (attempts + 1) << "/10)\n";
            attempts++;
            continue;
        }

        size_t remaining = size - totalReceived;
        std::vector<uint8_t> temp(remaining);

#ifdef _WIN32
        int received = ::recv(sockfd, reinterpret_cast<char*>(temp.data()), static_cast<int>(remaining), 0);
        if (received <= 0) {
            int err = WSAGetLastError();
            throw std::runtime_error("Socket recv failed: WSA error " + std::to_string(err));
        }
#else
        ssize_t received = ::recv(sockfd, temp.data(), remaining, 0);
        if (received <= 0) {
            throw std::runtime_error("Socket recv failed: " + std::string(strerror(errno)));
        }
#endif

        buffer.insert(buffer.end(), temp.begin(), temp.begin() + received);
        totalReceived += static_cast<size_t>(received);
        attempts = 0; // reset on success
    }

    return buffer;
}




void SocketWrapper::setTimeout(int seconds) {
#ifdef _WIN32
    DWORD timeout = seconds * 1000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) < 0 ||
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) < 0) {
        throw std::runtime_error("Failed to set socket timeout (Windows)");
    }
#else
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        throw std::runtime_error("Failed to set socket timeout (Linux)");
    }
#endif
}



void SocketWrapper::sendTo(const std::vector<uint8_t>& data, const sockaddr_in& addr) {
    size_t sent = ::sendto(sockfd, reinterpret_cast<const char*>(data.data()), data.size(), 0,
        reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    if (sent < 0) {
        throw std::runtime_error("Socket sendTo failed");
    }
}

std::vector<uint8_t> SocketWrapper::recvFrom(size_t size) {
    std::vector<uint8_t> buffer(size);
    sockaddr_in fromAddr;
    socklen_t fromLen = sizeof(fromAddr);
    size_t received = ::recvfrom(sockfd, reinterpret_cast<char*>(buffer.data()), size, 0,
        reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
    if (received <= 0) {
        throw std::runtime_error("Socket recvFrom failed");
    }
    buffer.resize(received);
    return buffer;
}

int SocketWrapper::getSocket() const {
    return sockfd;
}

bool SocketWrapper::isConnected() const {
    if (sockfd < 0) return false;
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
        return false;
    }

    char buf;
    int result = ::recv(sockfd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
    if (result == 0) {
        return false;
    } else if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;
        }
        return false;
    }

    return true;
}
