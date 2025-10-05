#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace Struct {

    enum class ByteOrder { LittleEndian, BigEndian, Native };

    struct FmtToken {
        char type;
        int count;
    };

    struct ParsedFormat {
        ByteOrder byteOrder;
        bool useAlignment = false; // Add this member to fix the error  
        std::vector<FmtToken> tokens;
        size_t size = 0;
    };

    struct Value {
        enum Type { INT, BYTES } type;
        int i;
        std::vector<uint8_t> bytes;

        static Value fromInt(int val);
        static Value fromBytes(const std::vector<uint8_t>& val);
    };

    bool isLittleEndian();
    ParsedFormat parseFormat(const std::string& format);

    std::vector<uint8_t> pack(const std::string& format, const std::vector<Value>& values);
    std::vector<Value> unpack(const std::string& format, const std::vector<uint8_t>& data);
    std::string bytesToHex(const std::vector<uint8_t>& data);
    std::string decodeString(const std::vector<uint8_t>& bytes, const std::string& encoding = "UTF-8");

}
