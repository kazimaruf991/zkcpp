#pragma once
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>

class Attendance {
public:
    int uid = 0;
    std::string user_id;
    std::tm timestamp;
    int status = 0;
    int punch = 0;

    Attendance(const std::string& userId, const std::tm& ts, int st, int pn = 0, int u = 0)
        : uid(u), user_id(userId), timestamp(ts), status(st), punch(pn) {
    }

    std::string toString() const {
        return "<Attendance>: " + user_id + " : " + formatTimestamp(timestamp) +
            " (" + std::to_string(status) + ", " + std::to_string(punch) + ")";
    }

    friend std::ostream& operator<<(std::ostream& os, const Attendance& a) {
        os << a.toString();
        return os;
    }

    std::string formatTimestamp(const std::tm& t) const {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
            t.tm_year, t.tm_mon, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);
        return std::string(buffer);
    }

};
