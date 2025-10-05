#pragma once
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>


class User {
public:
    static constexpr const char* encoding = "UTF-8";

    int uid;
    std::string name;
    int privilege;
    std::string password;
    std::string group_id;
    std::string user_id;
    uint32_t card;
    User() : uid(0), privilege(0), card(0) {};

    User(int uid, const std::string& name, int privilege,
        const std::string& password = "", const std::string& group_id = "",
        const std::string& user_id = "", uint32_t card = 0);

    static User fromJson(const std::map<std::string, std::string>& json);

    std::vector<uint8_t> repack29() const;
    std::vector<uint8_t> repack73() const;

    bool isDisabled() const;
    bool isEnabled() const;
    int userType() const;

    std::string toString() const;
};

std::ostream& operator<<(std::ostream& os, const User& user);
