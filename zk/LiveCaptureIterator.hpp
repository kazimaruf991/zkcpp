#pragma once

#include <optional>
#include <vector>
#include "ZKDevice.hpp"
#include "Attendance.hpp"
#include "User.hpp"

class LiveCaptureIterator {
public:
    LiveCaptureIterator(ZKDevice& device, int timeout);
    ~LiveCaptureIterator();

    std::optional<Attendance> next();

private:
    ZKDevice& dev;
    std::vector<User> users;
    bool active;
};
