#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <algorithm> 
#include <iomanip> 
#include <climits>
#include <cstdint>
#include "DeviceConstant.hpp"
#include "ZKHelper.hpp"
#include "SocketWrapper.hpp"
#include "Struct.hpp"
#include "User.hpp"
#include "Finger.hpp"
#include "Attendance.hpp"

struct CommandResult {
    bool status;
    int code;
};


class ZKDevice {
public:
    // Constructors
    ZKDevice(const std::string& ip,
        uint16_t port = 4370,
        int timeout = 60,
        int password = 0,
        bool forceUdp = false,
        bool ommitPing = false,
        bool verbose = false,
        const std::string& encoding = "UTF-8");

    ZKDevice(const std::string& ip);

    // Public flags
    sockaddr_in address{};
    bool isConnect = false;
    bool isEnabled = true;
    bool forceUdp = false;
    bool ommitPing = false;
    bool verbose = false;
    bool tcp = true;
    std::string encoding;
    int timeout;
    SocketWrapper sock{ tcp, timeout }; // Default to TCP

    // Device stats
    int users = 0, fingers = 0, records = 0, dummy = 0, cards = 0;
    int fingersCap = 0, usersCap = 0, recCap = 0, faces = 0, facesCap = 0;
    int fingersAv = 0, usersAv = 0, recAv = 0;
    int nextUid = 1;
    std::string nextUserId = "1";
    int userPacketSize = 28;
    bool endLiveCapture = false;

    // Functions
    operator bool() const;
    bool createSocket();
    std::vector<uint8_t> createTcpTop(const std::vector<uint8_t>& packet);
    std::vector<uint8_t> createHeader(uint16_t command,
        const std::vector<uint8_t>& commandString,
        uint16_t sessionId,
        uint16_t& replyId);
    uint32_t testTcpTop(const std::vector<uint8_t>& packet);
    CommandResult sendCommand(uint16_t command,
        const std::vector<uint8_t>& commandString = {},
        size_t responseSize = 8);
    ZKDevice& connect();
    bool setSdkBuild1();
	bool disableDevice();
    int getExtendFmt();
    int getUserExtendFmt();
    int getFaceFunOn();
    int getCompatOldFirmware();
    int getFpVersion();
    void clearError(const std::vector<uint8_t>& commandString = {});
    int getFaceVersion();
    void ackOk();
    uint32_t getDataSize() const;
    std::string reverseHex(const std::string& hex);
    std::tm decodeTime(const std::vector<uint8_t>& t);
    std::tm decodeTimeHex(const std::vector<uint8_t>& timehex);
    uint32_t encodeTime(const std::tm& t);
    bool disconnect();
    bool enableDevice();
    std::string getFirmwareVersion();
    std::string getSerialNumber();
    std::string getPlatform();
    std::string getMacAddress();
    std::string getDeviceName();
    std::string getMachineConfiguration(std::string option);
    std::string getNetworkParameters();
    uint8_t getPinWidth();
	bool freeData();
    bool readSizes();
    bool unlock(uint16_t time = 3);
    bool getLockState();
    std::string toString() const;
    bool restart();
    bool writeLCD(int lineNumber, std::string text);
    bool clearLCD();
    std::tm getTime();
    bool setTime(const std::tm& t);
	bool poweroff();
	bool refreshData();
    bool setUser(
        int uid,
        std::string& name,
        int privilege,
        std::string& password,
        std::string& group_id,
        std::string& user_id,
        uint32_t card
    );
    void saveUserTemplate(const User& user, const std::vector<Finger>& fingers);
    void saveUserTemplate(int uid, const std::vector<Finger>& fingers);
    void saveUserTemplate(const std::string& user_id, const std::vector<Finger>& fingers);

    bool deleteUserTemplate(int uid = 0, int tempId = 0, const std::string& userId = "");
    bool deleteUser(int uid = 0, const std::string& userId = "");
    bool getUserTemplate(int uid, int tempId, const std::string& userId, Finger& outFinger);
    std::vector<Finger> getTemplates();
    std::vector<User> getUsers();
    bool cancelCapture();
    bool verifyUser();
    void registerEvent(uint32_t flags);
    bool enrollUser(int uid = 0, int tempId = 0, const std::string& userId = "");
    std::vector<Attendance> liveCapture(int newTimeout = 10);
    bool clearData();
    std::vector<Attendance> getAttendance();
    bool clearAttendance();
    std::string getIpPortString(const sockaddr_in& addr) const;


private:
	//Private members
    std::string ip;
    uint16_t port;
    int password;
    int sessionId = 0;
    uint16_t replyId = USHRT_MAX - 1;
    int response = 0;
    int tcpLength = 0;
    std::vector<uint8_t> dataRecv;
    std::vector<uint8_t> data;
    std::vector<Struct::Value> header;
    std::unique_ptr<ZKHelper> helper;

	//functions
    template<typename... Buffers> std::vector<uint8_t> concatBuffers(const Buffers&... buffers) const;
    std::vector<uint8_t> makeCommKey(uint32_t key, uint32_t session_id, uint8_t ticks = 50);
    int safeCast(const std::vector<uint8_t>& raw, int fallback = 0);
    std::vector<uint8_t> extractValue() const;
    std::vector<uint8_t> toBytes(const std::string& str);
    std::vector<uint8_t> createChecksum(std::vector<uint8_t>& p);
    std::vector<uint8_t> createChecksum(std::vector<Struct::Value>& p);
    std::vector<std::string> split(const std::string& s, const std::string& delim);
    void HR_saveUserTemplates(const std::vector<std::pair<User, std::vector<Finger>>>& userTemplates);
    void sendWithBuffer(const std::vector<uint8_t>& buffer);
    void sendChunk(const std::vector<uint8_t>& commandString);
    std::vector<uint8_t> readChunk(int start, int size);
    std::pair<std::vector<uint8_t>, size_t> readWithBuffer(int command, int fct = 0, int ext = 0);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> receiveTcpData(const std::vector<uint8_t>& dataRecv, int size);
    std::vector<uint8_t> receiveRawData(size_t size);
    std::vector<uint8_t> receiveChunk();
    void printHex(const std::vector<uint8_t>& data);
};

inline std::ostream& operator<<(std::ostream& os, const ZKDevice& zk) {
    os << "ZK " << (zk.tcp ? "tcp" : "udp")
        << "://" << zk.getIpPortString(zk.address)
        << " users[" << zk.userPacketSize << "]:" << zk.users << "/" << zk.usersCap
        << " fingers:" << zk.fingers << "/" << zk.fingersCap
        << ", records:" << zk.records << "/" << zk.recCap
        << " faces:" << zk.faces << "/" << zk.facesCap;
    return os;
}
