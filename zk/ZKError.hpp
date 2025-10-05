#pragma once

#include <stdexcept>
#include <string>

class ZKError : public std::exception {
public:
    explicit ZKError(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override { return message.c_str(); }

protected:
    std::string message;
};

class ZKErrorConnection : public ZKError {
public:
    explicit ZKErrorConnection(const std::string& msg) : ZKError(msg) {}
};

class ZKErrorResponse : public ZKError {
public:
    explicit ZKErrorResponse(const std::string& msg) : ZKError(msg) {}
};

class ZKNetworkError : public ZKError {
public:
    explicit ZKNetworkError(const std::string& msg) : ZKError(msg) {}
};
