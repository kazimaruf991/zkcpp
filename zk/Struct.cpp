#include "Struct.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm> 

namespace Struct {

    Value Value::fromInt(int val) {
        Value v;
        v.type = INT;
        v.i = val;
        return v;
    }

    Value Value::fromBytes(const std::vector<uint8_t>& val) {
        Value v;
        v.type = BYTES;
        v.bytes = val;
        return v;
    }

    bool isLittleEndian() {
        uint16_t x = 1;
        return *reinterpret_cast<uint8_t*>(&x) == 1;
    }

    ParsedFormat parseFormat(const std::string& format) {
        if (format.empty()) throw std::invalid_argument("Empty format");

        ParsedFormat pf;
        size_t pos = 0;
        char first = format[0];

        if (first == '<') { pf.byteOrder = ByteOrder::LittleEndian; pos++; }
        else if (first == '>') { pf.byteOrder = ByteOrder::BigEndian; pos++; }
        else if (first == '=') { pf.byteOrder = ByteOrder::Native; pos++; }
        else if (first == '@') { pf.byteOrder = ByteOrder::Native; pf.useAlignment = true; pos++; }
        else { pf.byteOrder = ByteOrder::LittleEndian; }

        while (pos < format.size()) {
            int count = 0;
            while (pos < format.size() && isdigit(format[pos])) {
                count = count * 10 + (format[pos++] - '0');
            }
            if (count == 0) count = 1;
            if (pos >= format.size()) throw std::invalid_argument("Incomplete format");

            char type = format[pos++];
            pf.tokens.push_back({ type, count });
        }

        return pf;
    }


    std::vector<uint8_t> pack(const std::string& format, const std::vector<Value>& values) {
        ParsedFormat pf = parseFormat(format);
        std::vector<uint8_t> buf;
        size_t vi = 0;

        auto alignOffset = [&](size_t alignment) {
            if (pf.useAlignment && alignment > 1) {
                size_t offset = buf.size();
                size_t padding = (alignment - (offset % alignment)) % alignment;
                for (size_t p = 0; p < padding; ++p) buf.push_back(0);
            }
            };

        for (const auto& tok : pf.tokens) {
            for (int i = 0; i < tok.count; ++i) {
                const Value& val = (tok.type != 'x') ? values[vi++] : Value{};

                switch (tok.type) {
                case 'B': case 'b':
                    alignOffset(1);
                    buf.push_back(static_cast<uint8_t>(val.i));
                    break;
                case 'H': {
                    alignOffset(2);
                    uint16_t x = static_cast<uint16_t>(val.i);
                    if (pf.byteOrder == ByteOrder::LittleEndian || (pf.byteOrder == ByteOrder::Native && isLittleEndian())) {
                        buf.push_back(x & 0xFF);
                        buf.push_back((x >> 8) & 0xFF);
                    }
                    else {
                        buf.push_back((x >> 8) & 0xFF);
                        buf.push_back(x & 0xFF);
                    }
                    break;
                }
                case 'h': {
                    alignOffset(2);
                    int16_t x = static_cast<int16_t>(val.i);
                    if (pf.byteOrder == ByteOrder::LittleEndian || (pf.byteOrder == ByteOrder::Native && isLittleEndian())) {
                        buf.push_back(x & 0xFF);
                        buf.push_back((x >> 8) & 0xFF);
                    }
                    else {
                        buf.push_back((x >> 8) & 0xFF);
                        buf.push_back(x & 0xFF);
                    }
                    break;
                }
                case 'I': case 'i': {
                    alignOffset(4);
                    int32_t x = static_cast<int32_t>(val.i);
                    for (int b = 0; b < 4; ++b) {
                        int shift = (pf.byteOrder == ByteOrder::LittleEndian || (pf.byteOrder == ByteOrder::Native && isLittleEndian())) ? b : 3 - b;
                        buf.push_back((x >> (shift * 8)) & 0xFF);
                    }
                    break;
                }
                case 's': {
                    alignOffset(1);
                    for (int j = 0; j < tok.count; ++j)
                        buf.push_back(j < val.bytes.size() ? val.bytes[j] : 0);
                    i = tok.count - 1;
                    break;
                }
                case 'x':
                    alignOffset(1);
                    buf.push_back(0);
                    break;
                default:
                    throw std::invalid_argument("Unsupported type in pack");
                }
            }
        }

        return buf;
    }



    std::vector<Value> unpack(const std::string& format, const std::vector<uint8_t>& data) {
        ParsedFormat pf = parseFormat(format);
        std::vector<Value> out;
        size_t offset = 0;

        for (const auto& tok : pf.tokens) {
            for (int i = 0; i < tok.count; ++i) {
                switch (tok.type) {
                case 'B': out.push_back(Value::fromInt(data[offset++])); break;
                case 'b': out.push_back(Value::fromInt(static_cast<int8_t>(data[offset++]))); break;
                case 'H': {
                    uint16_t val = pf.byteOrder == ByteOrder::LittleEndian || (pf.byteOrder == ByteOrder::Native && isLittleEndian())
                        ? data[offset] | (data[offset + 1] << 8)
                        : (data[offset] << 8) | data[offset + 1];
                    out.push_back(Value::fromInt(val));
                    offset += 2;
                    break;
                }
                case 'h': {
                    int16_t val = pf.byteOrder == ByteOrder::LittleEndian || (pf.byteOrder == ByteOrder::Native && isLittleEndian())
                        ? data[offset] | (data[offset + 1] << 8)
                        : (data[offset] << 8) | data[offset + 1];
                    out.push_back(Value::fromInt(val));
                    offset += 2;
                    break;
                }
                case 'I': case 'i': {
                    int32_t val = 0;
                    for (int b = 0; b < 4; ++b) {
                        int shift = (pf.byteOrder == ByteOrder::LittleEndian || (pf.byteOrder == ByteOrder::Native && isLittleEndian())) ? b : 3 - b;
                        val |= data[offset++] << (shift * 8);
                    }
                    out.push_back(Value::fromInt(val));
                    break;
                }
                case 's': {
                    std::vector<uint8_t> str(tok.count);
                    std::memcpy(str.data(), &data[offset], tok.count);
                    out.push_back(Value::fromBytes(str));
                    offset += tok.count;
                    i = tok.count - 1;
                    break;
                }
                case 'x': offset++; break;
                default: throw std::invalid_argument("Unsupported type in unpack");
                }
            }
        }

        return out;
    }

    std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (uint8_t b : data)
            oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
        return oss.str();
    }

    std::string decodeString(const std::vector<uint8_t>& bytes, const std::string& encoding) {
        auto it = std::find(bytes.begin(), bytes.end(), 0);
        std::vector<uint8_t> cleanBytes(bytes.begin(), it);

        std::string result(cleanBytes.begin(), cleanBytes.end());

        size_t end = result.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) {
            result = result.substr(0, end + 1);
        }

        return result;
    }

}
