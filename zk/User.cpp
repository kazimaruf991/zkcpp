#include "User.hpp"
#include <sstream>
#include <iomanip> 
#include <algorithm>
#include "Struct.hpp"




User::User(int uid, const std::string& name, int privilege,
    const std::string& password, const std::string& group_id,
    const std::string& user_id, uint32_t card)
    : uid(uid), name(name), privilege(privilege),
    password(password), group_id(group_id),
    user_id(user_id), card(card) {
}

User User::fromJson(const std::map<std::string, std::string>& json) {
    return User(
        std::stoi(json.at("uid")),
        json.at("name"),
        std::stoi(json.at("privilege")),
        json.at("password"),
        json.at("group_id"),
        json.at("user_id"),
        static_cast<uint32_t>(std::stoul(json.at("card")))
    );
}

std::vector<uint8_t> User::repack29() const {
	std::vector<uint8_t> out = Struct::pack("<BHB5s8sIxBhI",
		{
			Struct::Value::fromInt(2),
			Struct::Value::fromInt(uid),
			Struct::Value::fromInt(static_cast<uint8_t>(privilege)),
			Struct::Value::fromBytes(std::vector<uint8_t>(password.begin(), password.end())),
			Struct::Value::fromBytes(std::vector<uint8_t>(name.begin(), name.end())),
			Struct::Value::fromInt(card),
			Struct::Value::fromInt(group_id.empty() ? 0 : std::stoi(group_id)),
			Struct::Value::fromInt(0), // padding
			Struct::Value::fromInt(std::stoi(user_id))
		}
	);
  
    return out;
}

std::vector<uint8_t> User::repack73() const {
	std::vector<uint8_t> out = Struct::pack("<BHB8s24sIB7sx24s",
		{
			Struct::Value::fromInt(2),
			Struct::Value::fromInt(uid),
			Struct::Value::fromInt(static_cast<uint8_t>(privilege)),
			Struct::Value::fromBytes(std::vector<uint8_t>(password.begin(), password.end())),
			Struct::Value::fromBytes(std::vector<uint8_t>(name.begin(), name.end())),
			Struct::Value::fromInt(card),
            Struct::Value::fromInt(1),
			Struct::Value::fromBytes(std::vector<uint8_t>(group_id.begin(), group_id.end())),
			Struct::Value::fromBytes(std::vector<uint8_t>(user_id.begin(), user_id.end()))
		}
	);

    return out;
}

bool User::isDisabled() const {
    return privilege & 1;
}

bool User::isEnabled() const {
    return !isDisabled();
}

int User::userType() const {
    return privilege & 0xE;
}

std::string User::toString() const {
    std::ostringstream oss;
    oss << "<User>: [uid:" << uid << ", name:" << name << ", user_id:" << user_id << "]";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const User& user) {
    std::string privilegeStr = (user.privilege == 0) ? "User" : "Admin-" + std::to_string(user.privilege);
    os << "-> UID #" << std::setw(5) << std::left << user.uid
        << " Name     : " << std::setw(27) << std::left << user.name
        << " Privilege : " << privilegeStr
        << "   Group ID : " << std::setw(8) << std::left << user.group_id
        << " User ID : " << std::setw(8) << std::left << user.user_id
        << " Password : " << std::setw(8) << std::left << user.password
        << " Card : " << user.card;
    return os;
}


