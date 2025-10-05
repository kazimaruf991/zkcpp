#include "LiveCaptureIterator.hpp"
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include "Struct.hpp"
#include "DeviceConstant.hpp"

LiveCaptureIterator::LiveCaptureIterator(ZKDevice& device, int timeout)
    : dev(device), users(device.getUsers()), active(true) {
    dev.cancelCapture();
    dev.verifyUser();
    if (!dev.isEnabled) dev.enableDevice();
    dev.registerEvent(DeviceConstant::EF_ATTLOG);
    dev.sock.setTimeout(timeout);
    dev.endLiveCapture = false;
}

LiveCaptureIterator::~LiveCaptureIterator() {
    dev.sock.setTimeout(dev.timeout);
    dev.registerEvent(0);
    if (!dev.isEnabled) dev.disableDevice();
}

std::optional<Attendance> LiveCaptureIterator::next() {
    if (!active || dev.endLiveCapture) return std::nullopt;

    try {
        auto dataRecv = dev.sock.recv(1032);
        dev.ackOk();

        std::vector<Struct::Value> header;
        std::vector<uint8_t> data;
        if (dev.tcp) {
            header = Struct::unpack("<HHHH", { dataRecv.begin() + 8, dataRecv.begin() + 16 });
            data = std::vector<uint8_t>(dataRecv.begin() + 16, dataRecv.end());
        }
        else {
            header = Struct::unpack("<4H", { dataRecv.begin(), dataRecv.begin() + 8 });
            data = std::vector<uint8_t>(dataRecv.begin() + 8, dataRecv.end());
        }

        if (header[0].i != DeviceConstant::CMD_REG_EVENT || data.empty()) return std::nullopt;

        std::string user_id;
        uint8_t status = 0, punch = 0;
        std::vector<uint8_t> timehex;
        size_t chunkSize = 0;

        if (data.size() >= 52) {
            auto fields = Struct::unpack("<24sBB6s20s", { data.begin(), data.begin() + 52 });
            user_id = Struct::decodeString(fields[0].bytes);
            status = fields[1].i;
            punch = fields[2].i;
            timehex = fields[3].bytes;
            chunkSize = 52;
        }
        else if (data.size() >= 37) {
            auto fields = Struct::unpack("<24sBB6s5s", { data.begin(), data.begin() + 37 });
            user_id = Struct::decodeString(fields[0].bytes);
            status = fields[1].i;
            punch = fields[2].i;
            timehex = fields[3].bytes;
            chunkSize = 37;
        }
        else if (data.size() >= 36) {
            auto fields = Struct::unpack("<24sBB6s4s", { data.begin(), data.begin() + 36 });
            user_id = Struct::decodeString(fields[0].bytes);
            status = fields[1].i;
            punch = fields[2].i;
            timehex = fields[3].bytes;
            chunkSize = 36;
        }
        else if (data.size() >= 32) {
            auto fields = Struct::unpack("<24sBB6s", { data.begin(), data.begin() + 32 });
            user_id = Struct::decodeString(fields[0].bytes);
            status = fields[1].i;
            punch = fields[2].i;
            timehex = fields[3].bytes;
            chunkSize = 32;
        }
        else {
            return std::nullopt;
        }

        data.erase(data.begin(), data.begin() + chunkSize);
        auto timestamp = dev.decodeTimeHex(timehex);

        int uid = 0;
        auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
            return u.user_id == user_id;
            });
        uid = (it != users.end()) ? it->uid : std::stoi(user_id);

        return Attendance(user_id, timestamp, status, punch, uid);
    }
    catch (const std::exception& e) {
        if (dev.verbose) std::cout << "[LiveCaptureIterator] Error: " << e.what() << "\n";
        active = false;
        return std::nullopt;
    }
}
