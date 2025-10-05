#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <map>

class Finger {
public:
    int size;
    int uid;
    int fid;
    int valid;
    std::vector<uint8_t> templateData;
    std::string mark;
    Finger();
    Finger(int uid, int fid, int valid, const std::vector<uint8_t>& templateData);

    std::vector<uint8_t> repack() const;
    std::vector<uint8_t> repackOnly() const;

    static Finger fromJson(const std::map<std::string, std::string>& json);
    std::map<std::string, std::string> toJson() const;

    bool operator==(const Finger& other) const;

    std::string toString() const;
    std::string dump() const;

private:
    static std::string hexEncode(const std::vector<uint8_t>& data, size_t start, size_t length);
    static std::string hexEncodeFull(const std::vector<uint8_t>& data);
};
