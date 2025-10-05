#include "Finger.hpp"
#include "Struct.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

Finger::Finger()
    : size(0), uid(0), fid(0), valid(0), templateData(), mark("") {
}

Finger::Finger(int uid, int fid, int valid, const std::vector<uint8_t>& templateData)
    : uid(uid), fid(fid), valid(valid), templateData(templateData) {
    size = static_cast<int>(templateData.size());
    mark = hexEncode(templateData, 0, 8) + "..." + hexEncode(templateData, size >= 8 ? size - 8 : 0, 8);
}

std::vector<uint8_t> Finger::repack() const {
	std::vector<uint8_t> out = Struct::pack("<HHbb" + std::to_string(size) + "s", 
        {
			Struct::Value::fromInt(size + 6),
			Struct::Value::fromInt(uid),
			Struct::Value::fromInt(fid),
			Struct::Value::fromInt(valid),
			Struct::Value::fromBytes(templateData)
        }
    );
    return out;
}

std::vector<uint8_t> Finger::repackOnly() const {
	std::vector<uint8_t> out = Struct::pack("<H" + std::to_string(size) + "s",
	    {
		    Struct::Value::fromInt(size),
		    Struct::Value::fromBytes(templateData)
	    }
    );
    return out;
}

Finger Finger::fromJson(const std::map<std::string, std::string>& json) {
    std::vector<uint8_t> tpl;
    std::string hex = json.at("template");
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        tpl.push_back(byte);
    }

    return Finger(
        std::stoi(json.at("uid")),
        std::stoi(json.at("fid")),
        std::stoi(json.at("valid")),
        tpl
    );
}

std::map<std::string, std::string> Finger::toJson() const {
    return {
        {"size", std::to_string(size)},
        {"uid", std::to_string(uid)},
        {"fid", std::to_string(fid)},
        {"valid", std::to_string(valid)},
        {"template", hexEncodeFull(templateData)}
    };
}

bool Finger::operator==(const Finger& other) const {
    return uid == other.uid &&
        fid == other.fid &&
        valid == other.valid &&
        templateData == other.templateData;
}

std::string Finger::toString() const {
    std::ostringstream oss;
    oss << "<Finger> [uid:" << std::setw(3) << uid
        << ", fid:" << fid
        << ", size:" << std::setw(4) << size
        << " v:" << valid
        << " t:" << mark << "]";
    return oss.str();
}

std::string Finger::dump() const {
    std::ostringstream oss;
    oss << "<Finger> [uid:" << std::setw(3) << uid
        << ", fid:" << fid
        << ", size:" << std::setw(4) << size
        << " v:" << valid
        << " t:" << hexEncodeFull(templateData) << "]";
    return oss.str();
}

std::string Finger::hexEncode(const std::vector<uint8_t>& data, size_t start, size_t length) {
    std::ostringstream oss;
    for (size_t i = start; i < start + length && i < data.size(); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string Finger::hexEncodeFull(const std::vector<uint8_t>& data) {
    return hexEncode(data, 0, data.size());
}
