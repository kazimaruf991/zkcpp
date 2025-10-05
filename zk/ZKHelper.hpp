#pragma once

#include <string>
#include <cstdint>

class ZKHelper {
public:
    ZKHelper(const std::string& ip, uint16_t port = 4370);

    bool testPing() const;
    bool testTCP() const;
    bool testUDP() const;

private:
    std::string ip_;
    uint16_t port_;
};
