#include <iostream>
#include <cstdint>
#include <array>
#include <string>
#include <sstream>
#include <type_traits>
#include <limits>
#include <ctime>
#include "Struct.hpp"
#include "ZKDevice.hpp"
#include "DeviceConstant.hpp"
#include "ZKError.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include "User.hpp"
#include "Finger.hpp"

ZKDevice::ZKDevice(const std::string& ip,
	uint16_t port,
	int timeout,
	int password,
	bool forceUdp,
	bool ommitPing,
	bool verbose,
	const std::string& encoding)
	: ip(ip), port(port), timeout(timeout), password(password),
	forceUdp(forceUdp), ommitPing(ommitPing), verbose(verbose),
	encoding(encoding), tcp(!forceUdp)
{
	if (sock.getSocket() >= 0) {
#ifdef _WIN32
		setsockopt(sock.getSocket(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
		struct timeval tv { timeout, 0 };
		setsockopt(sock.getSocket(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
	}

	// UDP socket
	if (sock.getSocket() >= 0) {
#ifdef _WIN32
		setsockopt(sock.getSocket(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
		struct timeval tv { timeout, 0 };
		setsockopt(sock.getSocket(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
	}

	helper = std::make_unique<ZKHelper>(ip, port);

	address.sin_family = AF_INET;
	address.sin_port = htons(port);
#ifdef _WIN32
	IN_ADDR addr;
	if (InetPtonA(AF_INET, ip.c_str(), &addr) == 1) {
		address.sin_addr = addr;
	}
	else {
		address.sin_addr.s_addr = INADDR_NONE;
	}
#else
	address.sin_addr.s_addr = inet_addr(ip.c_str());
#endif
}

ZKDevice::ZKDevice(const std::string& ip)
	: ZKDevice(ip, 4370, 60, 0, false, false, false, "UTF-8") {
}

std::vector<uint8_t> ZKDevice::makeCommKey(uint32_t key, uint32_t session_id, uint8_t ticks) {
	uint32_t k = 0;

	// Bit reversal logic
	for (int i = 0; i < 32; ++i) {
		if (key & (1U << i)) {
			k = (k << 1) | 1;
		}
		else {
			k <<= 1;
		}
	}

	k += session_id;

	// Break into bytes
	std::array<uint8_t, 4> bytes = {
		static_cast<uint8_t>((k >> 0) & 0xFF),
		static_cast<uint8_t>((k >> 8) & 0xFF),
		static_cast<uint8_t>((k >> 16) & 0xFF),
		static_cast<uint8_t>((k >> 24) & 0xFF)
	};

	// XOR with 'ZKSO'
	bytes[0] ^= 'Z';
	bytes[1] ^= 'K';
	bytes[2] ^= 'S';
	bytes[3] ^= 'O';

	// Swap 16-bit halves
	uint16_t h1 = static_cast<uint16_t>(bytes[0] | (bytes[1] << 8));
	uint16_t h2 = static_cast<uint16_t>(bytes[2] | (bytes[3] << 8));

	bytes[0] = h2 & 0xFF;
	bytes[1] = (h2 >> 8) & 0xFF;
	bytes[2] = h1 & 0xFF;
	bytes[3] = (h1 >> 8) & 0xFF;

	// Final XOR with ticks
	uint8_t B = ticks & 0xFF;
	return {
		static_cast<uint8_t>(bytes[0] ^ B),
		static_cast<uint8_t>(bytes[1] ^ B),
		B,
		static_cast<uint8_t>(bytes[3] ^ B)
	};
}

ZKDevice::operator bool() const {
	return isConnect;
}

bool ZKDevice::createSocket() {

	// If TCP, connect to address
	if (tcp) {
		sock.connect(address);
	}

	return true;
}

template<typename... Buffers>
std::vector<uint8_t> ZKDevice::concatBuffers(const Buffers&... buffers) const {
	std::vector<uint8_t> result;
	int dummy[] = { 0, (result.insert(result.end(), buffers.begin(), buffers.end()), 0)... };
	(void)dummy;
	return result;
}

std::vector<uint8_t> ZKDevice::createTcpTop(const std::vector<uint8_t>& packet) {
	std::vector<uint8_t> top = Struct::pack("<HHI", { Struct::Value::fromInt(DeviceConstant::MACHINE_PREPARE_DATA_1), Struct::Value::fromInt(DeviceConstant::MACHINE_PREPARE_DATA_2), Struct::Value::fromInt(static_cast<uint32_t>(packet.size())) });
	return concatBuffers(top, packet);
}

std::vector<uint8_t> ZKDevice::createHeader(uint16_t command, const std::vector<uint8_t>& commandString, uint16_t sessionId, uint16_t& replyId) {
	std::vector<uint8_t> buf = Struct::pack("<4H", { Struct::Value::fromInt(command), Struct::Value::fromInt(0), Struct::Value::fromInt(sessionId), Struct::Value::fromInt(replyId) });
	buf = concatBuffers(buf, commandString);
	std::string format = "<8B";
	if (!commandString.empty()) {
		format += std::to_string(commandString.size()) + "B";
	}
	std::vector<Struct::Value> unpacked = Struct::unpack(format, buf);

	std::vector<uint8_t> checksumBuf = createChecksum(unpacked);

	uint16_t checksum = Struct::unpack("<H", checksumBuf)[0].i;

	replyId = (replyId + 1);

	if (replyId >= USHRT_MAX) {
		replyId -= USHRT_MAX;
	}

	buf = Struct::pack("<4H", { Struct::Value::fromInt(command), Struct::Value::fromInt(checksum), Struct::Value::fromInt(sessionId), Struct::Value::fromInt(replyId) });
	return concatBuffers(buf, commandString);
}


std::vector<uint8_t> ZKDevice::createChecksum(std::vector<Struct::Value>& p) {
	size_t l = p.size();
	int32_t checksum = 0;

	while (l > 1) {

		std::vector<uint8_t> packed = Struct::pack("<BB", { p[0], p[1] });
		checksum += Struct::unpack("H", packed)[0].i;

		p = std::vector<Struct::Value>(p.begin() + 2, p.end());

		if (checksum > USHRT_MAX) {
			checksum -= USHRT_MAX;
		}

		l -= 2;
	}

	if (l == 1) {
		checksum += p.back().i;
	}

	while (checksum > USHRT_MAX) {
		checksum -= USHRT_MAX;
	}

	checksum = ~checksum;

	while (checksum < 0) {
		checksum += USHRT_MAX;
	}

	std::vector<uint8_t> result = Struct::pack("<H", { Struct::Value::fromInt(checksum) });
	return result;
}

std::vector<uint8_t> ZKDevice::createChecksum(std::vector<uint8_t>& p) {
	size_t l = p.size();
	uint32_t checksum = 0;
	size_t i = 0;

	while (l > 1) {
		uint16_t part = static_cast<uint16_t>(p[i]) | (static_cast<uint16_t>(p[i + 1]) << 8);
		checksum += part;

		if (checksum > USHRT_MAX) {
			checksum -= USHRT_MAX;
		}

		i += 2;
		l -= 2;
	}

	if (l == 1) {
		checksum += p[i];
	}

	while (checksum > USHRT_MAX) {
		checksum -= USHRT_MAX;
	}

	checksum = ~checksum;

	while (checksum < 0) {
		checksum += USHRT_MAX;
	}

	std::vector<uint8_t> result = Struct::pack("<H", { Struct::Value::fromInt(static_cast<uint16_t>(checksum)) });
	return result;
}

uint32_t ZKDevice::testTcpTop(const std::vector<uint8_t>& packet) {
	if (packet.size() <= 8) {
		return 0;
	}

	std::vector<Struct::Value> tcpHeader = Struct::unpack("<HHI", std::vector<uint8_t>(packet.begin(), packet.begin() + 8));

	if (tcpHeader[0].i == DeviceConstant::MACHINE_PREPARE_DATA_1 && tcpHeader[1].i == DeviceConstant::MACHINE_PREPARE_DATA_2) {
		return tcpHeader[2].i;
	}

	return 0;
}

CommandResult ZKDevice::sendCommand(uint16_t command, const std::vector<uint8_t>& commandString, size_t responseSize) {
	if (command != DeviceConstant::CMD_CONNECT && command != DeviceConstant::CMD_AUTH && !isConnect) {
		throw ZKErrorConnection("Instance is not connected.");
	}

	std::vector<uint8_t> buf = createHeader(command, commandString, sessionId, replyId);

	try {
		if (tcp) {
			std::vector<uint8_t> top = createTcpTop(buf);

			sock.send(top);

			std::vector<uint8_t> receivedData;

			if (command == DeviceConstant::_CMD_READ_BUFFER && responseSize > 1024)
			{
				receivedData = sock.recv(responseSize + 8);
			}
			else {
				receivedData = sock.recv(responseSize + 8);
			}

			tcpLength = testTcpTop(receivedData);
			if (tcpLength == 0) {
				throw ZKNetworkError("TCP packet invalid");
			}

			header = Struct::unpack("<4H", std::vector<uint8_t>(receivedData.begin() + 8, receivedData.begin() + 16));
			dataRecv.assign(receivedData.begin() + 8, receivedData.end());
		}
		else {
			sock.sendTo(buf, address);

			dataRecv = sock.recv(responseSize);
			header = Struct::unpack("<4H", std::vector<uint8_t>{dataRecv.begin(), dataRecv.begin() + 8});
		}
	}
	catch (const std::exception& e) {
		throw ZKNetworkError(e.what());
	}

	response = header[0].i;
	replyId = header[3].i;
	data.assign(dataRecv.begin() + 8, dataRecv.end());

	if (response == DeviceConstant::CMD_ACK_OK || response == DeviceConstant::CMD_PREPARE_DATA || response == DeviceConstant::CMD_DATA) {
		return { true, response };
	}

	return { false, response };
}


ZKDevice& ZKDevice::connect() {
	endLiveCapture = false;

	if (!ommitPing && !helper->testPing()) {
#ifdef _WIN32
		char ipStr[INET_ADDRSTRLEN] = { 0 };
		InetNtopA(AF_INET, &(address.sin_addr), ipStr, INET_ADDRSTRLEN);
		throw ZKNetworkError("Can't reach device (ping " + std::string(ipStr) + ")");
#else
		throw ZKNetworkError("Can't reach device (ping " + std::string(inet_ntoa(address.sin_addr)) + ")");
#endif
	}

	if (!forceUdp && helper->testTCP() == 0) {
		userPacketSize = 72;
	}

	createSocket();

	sessionId = 0;
	replyId = USHRT_MAX - 1;

	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_CONNECT);
	sessionId = header[2].i;

	if (cmdResponse.code == DeviceConstant::CMD_ACK_UNAUTH) {
		if (verbose) {
			std::cout << "Try auth" << std::endl;
		}

		std::vector<uint8_t> commandString = makeCommKey(password, sessionId);
		cmdResponse = sendCommand(DeviceConstant::CMD_AUTH, commandString);
	}

	if (cmdResponse.status) {
		isConnect = true;
		return *this;
	}
	else {
		if (cmdResponse.code == DeviceConstant::CMD_ACK_UNAUTH) {
			throw ZKErrorResponse("Unauthenticated");
		}
		if (verbose) {
			std::cout << "Connect error response: " << cmdResponse.code << std::endl;
		}
		throw ZKErrorResponse("Invalid response: Can't connect");
	}
}

bool ZKDevice::setSdkBuild1() {
	constexpr uint16_t command = DeviceConstant::CMD_OPTIONS_WRQ;
	const std::vector<uint8_t> commandString = { 'S','D','K','B','u','i','l','d','=','1' };

	CommandResult cmdResponse = sendCommand(command, commandString);

	return cmdResponse.status;
}

bool ZKDevice::disableDevice() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_DISABLEDEVICE);
	if (cmdResponse.status)
	{
		isEnabled = false;
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to disable device");
	}
}

int ZKDevice::safeCast(const std::vector<uint8_t>& raw, int fallback) {
	try {
		std::string str(raw.begin(), raw.end());
		return std::stoi(str);
	}
	catch (...) {
		return fallback;
	}
}


std::vector<uint8_t> ZKDevice::extractValue() const {
	auto it = std::find(data.begin(), data.end(), '=');
	if (it == data.end()) return {};

	std::vector<uint8_t> sliced(it + 1, data.end());
	auto nullPos = std::find(sliced.begin(), sliced.end(), '\0');
	if (nullPos != sliced.end()) sliced.resize(nullPos - sliced.begin());

	return sliced;
}


int ZKDevice::getExtendFmt() {
	constexpr uint16_t command = DeviceConstant::CMD_OPTIONS_RRQ;
	const std::vector<uint8_t> commandString = { '~','E','x','t','e','n','d','F','m','t','\0' };
	size_t responseSize = 1024;

	CommandResult cmdResponse = sendCommand(command, commandString, responseSize);
	if (cmdResponse.status) {
		std::vector<uint8_t> fmt = extractValue();
		return fmt.empty() ? 0 : safeCast(fmt);
	}
	else {
		clearError(commandString);
		return -1;
	}
}

int ZKDevice::getUserExtendFmt() {
	constexpr uint16_t command = DeviceConstant::CMD_OPTIONS_RRQ;
	const std::vector<uint8_t> commandString = { '~','U','s','e','r','E','x','t','F','m','t','\0' };
	size_t responseSize = 1024;

	CommandResult cmdResponse = sendCommand(command, commandString, responseSize);
	if (cmdResponse.status) {
		std::vector<uint8_t> fmt = extractValue();
		return fmt.empty() ? 0 : safeCast(fmt);
	}
	else {
		clearError(commandString);
		return -1;
	}
}

int ZKDevice::getFaceFunOn() {
	constexpr uint16_t command = DeviceConstant::CMD_OPTIONS_RRQ;
	const std::vector<uint8_t> commandString = { 'F','a','c','e','F','u','n','O','n','\0' };
	size_t responseSize = 1024;

	CommandResult cmdResponse = sendCommand(command, commandString, responseSize);
	if (cmdResponse.status) {
		std::vector<uint8_t> response = extractValue();
		return response.empty() ? 0 : safeCast(response);
	}
	else {
		clearError(commandString);
		return -1;
	}
}

int ZKDevice::getCompatOldFirmware() {
	constexpr uint16_t command = DeviceConstant::CMD_OPTIONS_RRQ;
	const std::vector<uint8_t> commandString = { 'C','o','m','p','a','t','O','l','d','F','i','r','m','w','a','r','e','\0' };
	size_t responseSize = 1024;

	CommandResult cmdResponse = sendCommand(command, commandString, responseSize);
	if (cmdResponse.status) {
		std::vector<uint8_t> response = extractValue();
		return response.empty() ? 0 : safeCast(response);
	}
	else {
		clearError(commandString);
		return -1;
	}
}

int ZKDevice::getFpVersion() {
	constexpr uint16_t command = DeviceConstant::CMD_OPTIONS_RRQ;
	const std::vector<uint8_t> commandString = { '~','Z','K','F','P','V','e','r','s','i','o','n','\0' };
	size_t responseSize = 1024;

	CommandResult cmdResponse = sendCommand(command, commandString, responseSize);
	if (cmdResponse.status) {
		std::vector<uint8_t> response = extractValue();
		response.erase(std::remove(response.begin(), response.end(), '='), response.end());
		return response.empty() ? 0 : safeCast(response);
	}
	else {
		throw ZKErrorResponse("Can't read fingerprint version");
	}
}

int ZKDevice::getFaceVersion() {
	constexpr uint16_t command = DeviceConstant::CMD_OPTIONS_RRQ;
	const std::vector<uint8_t> commandString = { 'Z','K','F','a','c','e','V','e','r','s','i','o','n','\0' };
	size_t responseSize = 1024;

	CommandResult cmdResponse = sendCommand(command, commandString, responseSize);
	if (cmdResponse.status) {
		std::vector<uint8_t> response = extractValue();
		response.erase(std::remove(response.begin(), response.end(), '='), response.end());
		return response.empty() ? 0 : safeCast(response);
	}
	else {
		throw ZKErrorResponse("Can't read face version");
	}

}

void ZKDevice::clearError(const std::vector<uint8_t>& commandString) {
	constexpr uint16_t CMD_ACK_ERROR = DeviceConstant::CMD_ACK_ERROR;
	constexpr uint16_t CMD_ACK_UNKNOWN = DeviceConstant::CMD_ACK_UNKNOWN;
	constexpr size_t responseSize = 1024;

	sendCommand(CMD_ACK_ERROR, commandString, responseSize);
	sendCommand(CMD_ACK_UNKNOWN, commandString, responseSize);
	sendCommand(CMD_ACK_UNKNOWN, commandString, responseSize);
	sendCommand(CMD_ACK_UNKNOWN, commandString, responseSize);
}

std::vector<uint8_t> ZKDevice::toBytes(const std::string& str) {
	return std::vector<uint8_t>(str.begin(), str.end());
}

void ZKDevice::ackOk() {
	// Create header buffer
	uint16_t responseSize = USHRT_MAX - 1;
	std::vector<uint8_t> buf = createHeader(DeviceConstant::CMD_ACK_OK, {}, sessionId, responseSize);

	try {
		if (tcp) {
			std::vector<uint8_t> top = createTcpTop(buf);
			sock.send(top); 
		}
		else {
			sock.sendTo(buf, address);
		}
	}
	catch (const std::exception& e) {
		throw ZKNetworkError(e.what());
	}
}

uint32_t ZKDevice::getDataSize() const {
	if (response == DeviceConstant::CMD_PREPARE_DATA) {
		if (data.size() < 4) {
			throw std::runtime_error("Insufficient data for size unpacking");
		}

		uint32_t size = Struct::unpack("I", std::vector<uint8_t> {data.begin(), data.begin() + 4})[0].i;
		return size;
	}
	else {
		return 0;
	}
}

std::string ZKDevice::reverseHex(const std::string& hex) {
	std::string data;
	size_t len = hex.length();
	if (len % 2 != 0) throw std::runtime_error("Hex string must have even length");

	for (int i = static_cast<int>(len / 2) - 1; i >= 0; --i) {
		data += hex.substr(i * 2, 2);
	}
	return data;
}

std::tm ZKDevice::decodeTime(const std::vector<uint8_t>& t) {
	if (t.size() < 4) throw std::runtime_error("Insufficient bytes for timestamp");

	uint32_t raw = Struct::unpack("<I", t)[0].i;

	std::tm d = {};
	d.tm_sec = raw % 60;  raw /= 60;
	d.tm_min = raw % 60;  raw /= 60;
	d.tm_hour = raw % 24;  raw /= 24;
	d.tm_mday = raw % 31 + 1; raw /= 31;
	d.tm_mon = raw % 12 + 1; raw /= 12;
	d.tm_year = raw + 2000;

	return d;
}

std::tm ZKDevice::decodeTimeHex(const std::vector<uint8_t>& timehex) {
	if (timehex.size() < 6) throw std::runtime_error("Expected 6 bytes for timehex");

	std::tm d = {};
	d.tm_year = timehex[0] + 2000;
	d.tm_mon = timehex[1];
	d.tm_mday = timehex[2];
	d.tm_hour = timehex[3];
	d.tm_min = timehex[4];
	d.tm_sec = timehex[5];

	return d;
}



uint32_t ZKDevice::encodeTime(const std::tm& t) {
	return (
		((t.tm_year % 100) * 12 * 31 + (t.tm_mon * 31) + t.tm_mday - 1) *
		(24 * 60 * 60) + (t.tm_hour * 60 + t.tm_min) * 60 + t.tm_sec
		);
}


bool ZKDevice::disconnect() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_EXIT);
	if (cmdResponse.status)
	{
		isConnect = false;
		if (sock.getSocket())
		{
			sock.close();
		}
		return true;
	}
	else {
		throw ZKErrorResponse("Unable to disconnet");
	}
}

bool ZKDevice::enableDevice() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_ENABLEDEVICE);
	if (cmdResponse.status)
	{
		isEnabled = true;
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to enable device");
	}
}

std::string ZKDevice::getFirmwareVersion() {
	auto cmdResponse = sendCommand(DeviceConstant::CMD_GET_VERSION, {}, 1024);
	if (cmdResponse.status) {
		auto it = std::find(data.begin(), data.end(), 0);
		std::string version(data.begin(), it);
		return version;
	}
	else {
		throw ZKErrorResponse("Can't read firmware version");
	}
}

std::string ZKDevice::getSerialNumber() {
	return getMachineConfiguration("~SerialNumber");
}

std::string ZKDevice::getPlatform() {
	return getMachineConfiguration("~Platform");
}

std::string ZKDevice::getMacAddress() {
	return getMachineConfiguration("MAC");
}
std::string ZKDevice::getDeviceName() {
	return getMachineConfiguration("~DeviceName");
}

std::string ZKDevice::getMachineConfiguration(std::string option) {
	while (!option.empty() && option.back() == '\0') {
		option.pop_back();
	}

	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_OPTIONS_RRQ, toBytes(option + '\0'), 1024);
	if (cmdResponse.status) {
		std::vector<uint8_t> platform = extractValue();
		return std::string(platform.begin(), platform.end());
	}
	else {
		throw ZKErrorResponse("Can't read " + option);
	}
}

std::string ZKDevice::getNetworkParameters() {
	std::string ipAddress = getMachineConfiguration("IPAddress");
	std::string netMask = getMachineConfiguration("NetMask");
	std::string gateWay = getMachineConfiguration("GATEIPAddress");

	if (!ipAddress.empty() && !netMask.empty() && !gateWay.empty())
	{
		return std::string("IP: " + ipAddress + ", NetMask: " + netMask + ", Gateway: " + gateWay);
	}
	else {
		throw ZKErrorResponse("Can't read network parameters");
	}
}

uint8_t ZKDevice::getPinWidth() {
	const uint16_t command = DeviceConstant::CMD_GET_PINWIDTH;
	const std::vector<uint8_t> commandString = { ' ', 'P' };
	const size_t responseSize = 9;

	auto cmdResponse = sendCommand(command, commandString, responseSize);
	if (cmdResponse.status) {
		auto it = std::find(data.begin(), data.end(), 0);
		if (it == data.begin()) throw std::runtime_error("Empty response before null");

		return static_cast<uint8_t>(*(data.begin()));
	}
	else {
		throw ZKErrorResponse("can't get pin width");
	}
}

bool ZKDevice::freeData() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_FREE_DATA);
	if (cmdResponse.status) {
		return true;
	}
	else
	{
		throw ZKErrorResponse("Failed to free data");
	}
}

bool ZKDevice::readSizes() {
	const uint16_t command = DeviceConstant::CMD_GET_FREE_SIZES;
	const size_t responseSize = 1024;

	auto cmdResponse = sendCommand(command, {}, responseSize);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("Failed to read sizes");
	}

	if (verbose) {
		for (uint8_t b : data) {
			printf("%02X", b);
		}
		printf("\n");
	}

	size_t size = data.size();
	if (size >= 80) {
		std::vector<Struct::Value> fields = Struct::unpack("<20i", std::vector<uint8_t>(data.begin(), data.begin() + 80));

		users = fields[4].i;
		fingers = fields[6].i;
		records = fields[8].i;
		dummy = fields[10].i; // ??? mystery meat
		cards = fields[12].i;
		fingersCap = fields[14].i;
		usersCap = fields[15].i;
		recCap = fields[16].i;
		fingersAv = fields[17].i;
		usersAv = fields[18].i;
		recAv = fields[19].i;

		data.erase(data.begin(), data.begin() + 80);
	}

	if (data.size() >= 12) {
		std::vector<Struct::Value> faceFields = Struct::unpack("<3i", std::vector<uint8_t>(data.begin(), data.begin() + 12));
		faces = faceFields[0].i;
		fingersCap = faceFields[2].i;
	}

	return true;
}

bool ZKDevice::unlock(uint16_t time) {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_UNLOCK, Struct::pack("<I", { Struct::Value::fromInt(time * 10) }));
	if (cmdResponse.status) {
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to unlock door");
	}
}

bool ZKDevice::getLockState() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_DOORSTATE_RRQ);
	if (cmdResponse.status)
	{
		return true;
	}
	else {
		return false;
	}
}

bool ZKDevice::restart() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_RESTART);
	if (cmdResponse.status) {
		isConnect = false;
		nextUid = 1;
		if (sock.getSocket()) {
			sock.close();
		}
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to restart device");
	}
}

bool ZKDevice::writeLCD(int lineNumber, std::string text) {
	std::vector<uint8_t> commandString = Struct::pack("<hb", { Struct::Value::fromInt(lineNumber), Struct::Value::fromInt(0) });
	commandString.push_back(' ');
	commandString.insert(commandString.end(), text.begin(), text.end());
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_WRITE_LCD, commandString);
	if (cmdResponse.status) {
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to write to LCD");
	}
}

bool ZKDevice::clearLCD() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_CLEAR_LCD);
	if (cmdResponse.status) {
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to clear LCD");
	}
}

std::tm ZKDevice::getTime() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_GET_TIME, {}, 1032);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("can't get time");
	}

	if (data.size() < 4) {
		throw std::runtime_error("Insufficient data for timestamp");
	}

	return decodeTime(std::vector<uint8_t>(data.begin(), data.begin() + 4));
}




std::string ZKDevice::getIpPortString(const sockaddr_in& addr) const {
#ifdef _WIN32
	char ipStr[INET_ADDRSTRLEN] = { 0 };
	if (InetNtopA(AF_INET, &(addr.sin_addr), ipStr, INET_ADDRSTRLEN) == nullptr) {
		throw std::runtime_error("Failed to convert IP address to string");
	}
	std::string ip = ipStr;
#else
	char ipStr[INET_ADDRSTRLEN] = { 0 };
	if (inet_ntop(AF_INET, &(addr.sin_addr), ipStr, INET_ADDRSTRLEN) == nullptr) {
		throw std::runtime_error("Failed to convert IP address to string");
	}
	std::string ip = ipStr;
#endif
	uint16_t port = ntohs(addr.sin_port);
	return ip + ":" + std::to_string(port);
}

std::string ZKDevice::toString() const {
	std::ostringstream oss;
	oss << "ZK " << (tcp ? "tcp" : "udp") << "://"
		<< getIpPortString(address)
		<< " users[" << userPacketSize << "]:" << users << "/" << usersCap
		<< " fingers:" << fingers << "/" << fingersCap
		<< ", records:" << records << "/" << recCap
		<< " faces:" << faces << "/" << facesCap;
	return oss.str();
}

bool ZKDevice::setTime(const std::tm& t) {
	std::vector<uint8_t> commandString = Struct::pack("<I", { Struct::Value::fromInt(encodeTime(t)) });
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_SET_TIME, commandString);
	if (cmdResponse.status) {
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to set time");
	}
}

bool ZKDevice::poweroff() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_POWEROFF, {}, 1032);
	if (cmdResponse.status) {
		isConnect = false;
		nextUid = 1;
		if (sock.getSocket()) {
			sock.close();
		}
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to poweroff device");
	}
}

bool ZKDevice::refreshData() {
	CommandResult cmdResponse = sendCommand(DeviceConstant::CMD_REFRESHDATA);
	if (cmdResponse.status) {
		return true;
	}
	else {
		throw ZKErrorResponse("Failed to refresh data");
	}
}

bool ZKDevice::setUser(int uid, std::string& name, int privilege, std::string& password, std::string& group_id, std::string& user_id, uint32_t card) {
	constexpr uint16_t command = DeviceConstant::CMD_USER_WRQ;

	if (uid < 0) {
		uid = nextUid;
		if (user_id.empty()) {
			user_id = nextUserId;
		}
	}

	std::string final_user_id = user_id.empty() ? std::to_string(uid) : user_id;

	if (privilege != DeviceConstant::USER_DEFAULT && privilege != DeviceConstant::USER_ADMIN) {
		privilege = DeviceConstant::USER_DEFAULT;
	}

	std::vector<uint8_t> commandString;

	if (userPacketSize == 28) {
		int group = group_id.empty() ? 0 : std::stoi(group_id);

		try {
			commandString = Struct::pack("<HB5s8sIxBHI",
				{
					Struct::Value::fromInt(uid),
					Struct::Value::fromInt(static_cast<uint8_t>(privilege)),
					Struct::Value::fromBytes(toBytes(password)),
					Struct::Value::fromBytes(toBytes(name)),
					Struct::Value::fromInt(card),
					Struct::Value::fromInt(static_cast<uint8_t>(group)),
					Struct::Value::fromInt(0),
					Struct::Value::fromInt(std::stoi(final_user_id))
				}
			);
		}
		catch (...) {
			if (verbose) std::cerr << "Error packing user for ZK6\n";
			throw ZKErrorResponse("Can't pack user");
		}

	}
	else {
		std::vector<uint8_t> name_pad = toBytes(name); name_pad.resize(24, 0);
		std::vector<uint8_t> card_bytes = Struct::pack("I", { Struct::Value::fromInt(card) });
		std::vector<uint8_t> password_bytes = toBytes(password); password_bytes.resize(8, 0);
		card_bytes = { card_bytes.begin(), card_bytes.begin() + 4 };
		std::vector<uint8_t> group_bytes(group_id.begin(), group_id.end());
		group_bytes.resize(7, 0);
		std::vector<uint8_t> user_bytes(final_user_id.begin(), final_user_id.end());
		user_bytes.resize(24, 0);

		commandString = Struct::pack("@HB8s24s4sx7sx24s",
			{
				Struct::Value::fromInt(uid),
				Struct::Value::fromInt(static_cast<uint8_t>(privilege)),
				Struct::Value::fromBytes(password_bytes),
				Struct::Value::fromBytes(name_pad),
				Struct::Value::fromBytes(card_bytes),
				Struct::Value::fromBytes(group_bytes),
				Struct::Value::fromBytes(user_bytes)
			}
		);
	}

	auto cmdResponse = sendCommand(command, commandString, 1024);
	if (verbose) std::cout << "Response: " << cmdResponse.status << std::endl;

	if (!cmdResponse.status) {
		throw ZKErrorResponse("Can't set user");
	}

	refreshData();

	if (nextUid == uid) nextUid++;
	if (nextUserId == final_user_id) nextUserId = std::to_string(nextUid);

	return true;
}

void ZKDevice::saveUserTemplate(const User& user, const std::vector<Finger>& fingers) {
	std::vector<Finger> normalizedFingers = fingers;
	if (normalizedFingers.size() == 1 && normalizedFingers[0].templateData.empty()) {
		normalizedFingers = { normalizedFingers[0] };
	}

	HR_saveUserTemplates({ {user, normalizedFingers} });
}

void ZKDevice::saveUserTemplate(int uid, const std::vector<Finger>& fingers) {
	const auto& users = getUsers();
	auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
		return u.uid == uid;
		});

	if (it != users.end()) {
		saveUserTemplate(*it, fingers);
	}
	else {
		throw ZKErrorResponse("Can't find user by UID");
	}
}

void ZKDevice::saveUserTemplate(const std::string& user_id, const std::vector<Finger>& fingers) {
	const auto& users = getUsers();
	auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
		return u.user_id == user_id;
		});

	if (it != users.end()) {
		saveUserTemplate(*it, fingers);
	}
	else {
		throw ZKErrorResponse("Can't find user by user_id");
	}
}


void ZKDevice::HR_saveUserTemplates(const std::vector<std::pair<User, std::vector<Finger>>>& userTemplates) {
	std::vector<uint8_t> upack;
	std::vector<uint8_t> fpack;
	std::vector<uint8_t> table;
	uint32_t fnum = 0x10;
	uint32_t tstart = 0;

	for (const auto& [user, fingers] : userTemplates) {
		if (user.uid <= 0 || user.name.empty()) {
			throw ZKErrorResponse("Invalid user in userTemplates list");
		}


		const auto userBytes = (userPacketSize == 28) ? user.repack29() : user.repack73();
		upack.insert(upack.end(), userBytes.begin(), userBytes.end());

		for (const auto& finger : fingers) {
			if (finger.templateData.empty() || finger.fid < 0 && finger.fid > 9) {
				throw ZKErrorResponse("Invalid finger template in userTemplates list");
			}

			const auto tfp = finger.repackOnly();
			const auto tableEntry = Struct::pack("<bHbI", {
				Struct::Value::fromInt(2),
				Struct::Value::fromInt(user.uid),
				Struct::Value::fromInt(fnum + finger.fid),
				Struct::Value::fromInt(tstart)
				});

			table.insert(table.end(), tableEntry.begin(), tableEntry.end());
			fpack.insert(fpack.end(), tfp.begin(), tfp.end());
			tstart += static_cast<uint32_t>(tfp.size());
		}
	}

	const auto head = Struct::pack("<III", {
		Struct::Value::fromInt(static_cast<int>(upack.size())),
		Struct::Value::fromInt(static_cast<int>(table.size())),
		Struct::Value::fromInt(static_cast<int>(fpack.size()))
		});

	std::vector<uint8_t> packet;
	packet.insert(packet.end(), head.begin(), head.end());
	packet.insert(packet.end(), upack.begin(), upack.end());
	packet.insert(packet.end(), table.begin(), table.end());
	packet.insert(packet.end(), fpack.begin(), fpack.end());

	sendWithBuffer(packet);

	const auto command = DeviceConstant::_CMD_SAVE_USERTEMPS;
	const auto commandString = Struct::pack("<IHH", {
		Struct::Value::fromInt(12),
		Struct::Value::fromInt(0),
		Struct::Value::fromInt(8)
		});

	CommandResult cmdResponse = sendCommand(command, commandString);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("Can't save userTemplates");
	}

	refreshData();
}

void ZKDevice::sendWithBuffer(const std::vector<uint8_t>& buffer) {
	constexpr size_t MAX_CHUNK = 1024;
	size_t size = buffer.size();

	freeData(); // clear device buffer

	uint32_t command = DeviceConstant::CMD_PREPARE_DATA;
	auto commandString = Struct::pack("<I", {
		Struct::Value::fromInt(static_cast<int>(size))
		});

	auto cmdResponse = sendCommand(command, commandString);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("Can't prepare data");
	}

	size_t remain = size % MAX_CHUNK;
	size_t packets = (size - remain) / MAX_CHUNK;
	size_t start = 0;

	for (size_t i = 0; i < packets; ++i) {
		std::vector<uint8_t> chunk(buffer.begin() + start, buffer.begin() + start + MAX_CHUNK);
		sendChunk(chunk);
		start += MAX_CHUNK;
	}

	if (remain > 0) {
		std::vector<uint8_t> chunk(buffer.begin() + start, buffer.end());
		sendChunk(chunk);
	}
}

void ZKDevice::sendChunk(const std::vector<uint8_t>& commandString) {
	uint32_t command = DeviceConstant::CMD_DATA;
	auto cmdResponse = sendCommand(command, commandString);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("Can't send chunk");
	}
}

bool ZKDevice::deleteUserTemplate(int uid, int tempId, const std::string& userId) {
	if (tcp && !userId.empty()) {
		auto commandString = Struct::pack("<24sB", {
			Struct::Value::fromBytes(std::vector<uint8_t>(userId.begin(), userId.end())),
			Struct::Value::fromInt(tempId)
			});
		auto cmdResponse = sendCommand(DeviceConstant::_CMD_DEL_USER_TEMP, commandString);
		return cmdResponse.status;
	}

	if (uid == 0) {
		auto users = getUsers();
		auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
			return u.user_id == userId;
			});
		if (it == users.end()) return false;
		uid = it->uid;
	}

	auto commandString = Struct::pack("<hb", {
		Struct::Value::fromInt(uid),
		Struct::Value::fromInt(tempId)
		});
	auto cmdResponse = sendCommand(DeviceConstant::CMD_DELETE_USERTEMP, commandString);
	return cmdResponse.status;
}

bool ZKDevice::deleteUser(int uid, const std::string& userId) {
	if (uid == 0) {
		auto users = getUsers();
		auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
			return u.user_id == userId;
			});
		if (it == users.end()) return false;
		uid = it->uid;
	}

	auto commandString = Struct::pack("<h", {
		Struct::Value::fromInt(uid)
		});
	auto cmdResponse = sendCommand(DeviceConstant::CMD_DELETE_USER, commandString);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("Can't delete user");
	}

	refreshData();
	if (uid == nextUid - 1) {
		nextUid = uid;
	}

	return true;
}

//std::optional<Finger> ZKDevice::getUserTemplate(int uid, int tempId, const std::string& userId) {
//	if (uid == 0) {
//		auto users = getUsers();
//		auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
//			return u.user_id == userId;
//			});
//		if (it == users.end()) return std::nullopt;
//		uid = it->uid;
//	}
//
//	for (int retries = 0; retries < 3; ++retries) {
//		auto commandString = Struct::pack("<hb", {
//			Struct::Value::fromInt(uid),
//			Struct::Value::fromInt(tempId)
//			});
//
//		auto cmdResponse = sendCommand(DeviceConstant::_CMD_GET_USERTEMP, commandString, 1032);
//		auto data = receiveChunk();
//		if (!data.empty()) {
//			if (data.size() >= 7 && std::equal(data.end() - 6, data.end(), std::vector<uint8_t>(6, 0).begin())) {
//				data.resize(data.size() - 6);
//			}
//			return Finger(uid, tempId, 1, data);
//		}
//		if (verbose) std::cout << "retry get_user_template\n";
//	}
//
//	if (verbose) std::cout << "Can't read/find finger\n";
//	return std::nullopt;
//}

bool ZKDevice::getUserTemplate(int uid, int tempId, const std::string& userId, Finger& outFinger) {
	if (uid == 0) {
		auto users = getUsers();
		auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
			return u.user_id == userId;
			});
		if (it == users.end()) {
			if (verbose) std::cout << "User not found: " << userId << "\n";
			return false;
		}
		uid = it->uid;
	}

	for (int retries = 0; retries < 3; ++retries) {
		auto commandString = Struct::pack("<hb", {
			Struct::Value::fromInt(uid),
			Struct::Value::fromInt(tempId)
			});

		auto cmdResponse = sendCommand(DeviceConstant::_CMD_GET_USERTEMP, commandString, 1032);
		auto data = receiveChunk();
		if (!data.empty()) {
			if (data.size() >= 7 &&
				std::equal(data.end() - 6, data.end(), std::vector<uint8_t>(6, 0).begin())) {
				data.resize(data.size() - 6);
			}
			outFinger = Finger(uid, tempId, 1, data);
			return true;
		}
		if (verbose) std::cout << "retry get_user_template\n";
	}

	if (verbose) std::cout << "Can't read/find finger\n";
	return false;
}


std::vector<Finger> ZKDevice::getTemplates() {
	readSizes();
	if (fingers == 0) return {};

	auto [templatedata, size] = readWithBuffer(DeviceConstant::CMD_DB_RRQ, DeviceConstant::FCT_FINGERTMP);
	if (size < 4) {
		if (verbose) std::cout << "WRN: no user data\n";
		return {};
	}

	int totalSize = Struct::unpack("<i", templatedata)[0].i;
	if (verbose) std::cout << "get template total size " << totalSize << ", size " << size << ", len " << templatedata.size() << "\n";

	std::vector<Finger> templates;
	templatedata.erase(templatedata.begin(), templatedata.begin() + 4);

	while (totalSize > 0 && templatedata.size() >= 6) {
		auto header = Struct::unpack("<HHbb", { templatedata.begin(), templatedata.begin() + 6 });
		int chunkSize = header[0].i;
		int uid = header[1].i;
		int fid = header[2].i;
		int valid = header[3].i;

		std::vector<uint8_t> templateBytes(templatedata.begin() + 6, templatedata.begin() + chunkSize);
		templates.emplace_back(uid, fid, valid, templateBytes);

		templatedata.erase(templatedata.begin(), templatedata.begin() + chunkSize);
		totalSize -= chunkSize;
	}

	return templates;
}

std::vector<uint8_t> ZKDevice::readChunk(int start, int size) {
	for (int retries = 0; retries < 3; ++retries) {
		auto commandString = Struct::pack("<ii", {
			Struct::Value::fromInt(start),
			Struct::Value::fromInt(size)
			});

		size_t responseSize = tcp ? size + 32 : 1032;
		auto cmdResponse = sendCommand(DeviceConstant::_CMD_READ_BUFFER, commandString, responseSize);
		auto receivedData = receiveChunk();

		if (!receivedData.empty()) return receivedData;
	}

	throw ZKErrorResponse("can't read chunk " + std::to_string(start) + ":[" + std::to_string(size) + "]");
}

std::pair<std::vector<uint8_t>, size_t> ZKDevice::readWithBuffer(int command, int fct, int ext) {
	size_t MAX_CHUNK = tcp ? 0xFFc0 : 16 * 1024;

	auto commandString = Struct::pack("<bhii", {
		Struct::Value::fromInt(1),
		Struct::Value::fromInt(command),
		Struct::Value::fromInt(fct),
		Struct::Value::fromInt(ext)
		});

	if (verbose) std::cout << "[readWithBuffer] Sending PREPARE_BUFFER command\n";

	auto cmdResponse = sendCommand(DeviceConstant::_CMD_PREPARE_BUFFER, commandString, 1024);
	if (!cmdResponse.status) throw ZKErrorResponse("RWB Not supported");

	if (cmdResponse.code == DeviceConstant::CMD_DATA) {
		if (tcp) {
			if (verbose) std::cout << "[readWithBuffer] TCP CMD_DATA - data.size(): " << data.size() << ", tcpLength: " << tcpLength << "\n";
			if (data.size() < (tcpLength - 8)) {
				size_t need = (tcpLength - 8) - data.size();
				if (verbose) std::cout << "[readWithBuffer] Need more data: " << need << "\n";
				auto moreData = receiveRawData(need);
				std::vector<uint8_t> fullData = data;
				fullData.insert(fullData.end(), moreData.begin(), moreData.end());
				if (verbose) std::cout << "[readWithBuffer] Final fullData.size(): " << fullData.size() << "\n";
				return { fullData, fullData.size() };
			}
			else {
				if (verbose) std::cout << "[readWithBuffer] Enough data - returning\n";
				return { data, data.size() };
			}
		}
		else {
			if (verbose) std::cout << "[readWithBuffer] Non-TCP CMD_DATA - returning\n";
			return { data, data.size() };
		}
	}

	if (data.size() < 5) throw ZKErrorResponse("Insufficient data for size unpack");

	int size = Struct::unpack("<I", { data.begin() + 1, data.begin() + 5 })[0].i;
	if (verbose) std::cout << "[readWithBuffer] Payload size: " << size << "\n";

	if (size == 0 || size > 10 * 1024 * 1024) throw ZKErrorResponse("Invalid buffer size");

	size_t remain = size % MAX_CHUNK;
	size_t packets = (size - remain) / MAX_CHUNK;
	if (verbose) std::cout << "[readWithBuffer] rwb: " << packets << " packets of max " << MAX_CHUNK << " bytes, and extra " << remain << " bytes remain\n";

	std::vector<uint8_t> fullData;
	size_t start = 0;

	for (size_t i = 0; i < packets; ++i) {
		auto chunk = readChunk(start, MAX_CHUNK);
		if (chunk.empty()) throw ZKErrorResponse("Failed to read chunk at offset " + std::to_string(start));
		fullData.insert(fullData.end(), chunk.begin(), chunk.end());
		start += MAX_CHUNK;
	}

	if (remain > 0) {
		auto chunk = readChunk(start, remain);
		if (chunk.empty()) throw ZKErrorResponse("Failed to read final chunk at offset " + std::to_string(start));
		fullData.insert(fullData.end(), chunk.begin(), chunk.end());
		start += remain;
	}

	freeData();
	if (verbose) std::cout << "[readWithBuffer] Final fullData.size(): " << fullData.size() << ", total bytes read: " << start << "\n";

	return { fullData, start };
}


std::pair<std::vector<uint8_t>, std::vector<uint8_t>> ZKDevice::receiveTcpData(const std::vector<uint8_t>& dataRecv, int size) {
	std::vector<uint8_t> data;

	if (dataRecv.size() < 16) {
		if (verbose) std::cout << "[receiveTcpData] Packet too short - aborting\n";
		return { {}, {} };
	}

	int tcpLen = testTcpTop(dataRecv);
	if (verbose) std::cout << "[receiveTcpData] tcp_length: " << tcpLen << ", expected size: " << size << "\n";

	if (tcpLen <= 0) {
		if (verbose) std::cout << "[receiveTcpData] Invalid TCP packet - aborting\n";
		return { {}, {} };
	}

	if ((tcpLen - 8) < size) {
		if (verbose) std::cout << "[receiveTcpData] TCP length too small - partial read\n";

		auto [resp1, bh1] = receiveTcpData(dataRecv, tcpLen - 8);
		data.insert(data.end(), resp1.begin(), resp1.end());
		size -= static_cast<int>(resp1.size());

		if (verbose) std::cout << "[receiveTcpData] Remaining size to fetch: " << size << "\n";

		auto more = sock.recv(size + 16);
		std::vector<uint8_t> combined = bh1;
		combined.insert(combined.end(), more.begin(), more.end());

		if (verbose) std::cout << "[receiveTcpData] Combined packet size: " << combined.size() << "\n";

		auto [resp2, bh2] = receiveTcpData(combined, size);
		data.insert(data.end(), resp2.begin(), resp2.end());

		if (verbose) std::cout << "[receiveTcpData] Final chunk: " << resp2.size() << ", trailing header: " << bh2.size() << "\n";
		return { data, bh2 };
	}

	int received = static_cast<int>(dataRecv.size());
	int response = Struct::unpack("<HHHH", { dataRecv.begin() + 8, dataRecv.begin() + 16 })[0].i;

	if (received >= (size + 32)) {
		if (response == DeviceConstant::CMD_DATA) {
			std::vector<uint8_t> resp(dataRecv.begin() + 16, dataRecv.begin() + 16 + size);
			std::vector<uint8_t> broken(dataRecv.begin() + 16 + size, dataRecv.end());
			if (verbose) std::cout << "[receiveTcpData] Full response - resp.size(): " << resp.size() << ", broken.size(): " << broken.size() << "\n";
			return { resp, broken };
		}
		else {
			if (verbose) std::cout << "[receiveTcpData] Unexpected response code: " << response << "\n";
			return { {}, {} };
		}
	}
	else {
		if (verbose) std::cout << "[receiveTcpData] Incomplete DATA - valid bytes: " << received - 16 << "\n";

		if (dataRecv.size() >= (size + 16)) {
			data.insert(data.end(), dataRecv.begin() + 16, dataRecv.begin() + 16 + size);
		}
		else {
			data.insert(data.end(), dataRecv.begin() + 16, dataRecv.end());
		}

		size -= (received - 16);
		if (verbose) std::cout << "[receiveTcpData] Remaining size: " << size << "\n";

		std::vector<uint8_t> brokenHeader;
		if (size < 0 && static_cast<size_t>(-size) <= dataRecv.size()) {
			brokenHeader.assign(dataRecv.end() + size, dataRecv.end());
			if (verbose) std::cout << "[receiveTcpData] Broken header detected - brokenHeader.size(): " << brokenHeader.size() << "\n";
		}

		if (size > 0) {
			auto more = receiveRawData(size);
			data.insert(data.end(), more.begin(), more.end());
			if (verbose) std::cout << "[receiveTcpData] Final insert - data.size(): " << data.size() << "\n";
		}

		return { data, brokenHeader };
	}
}


std::vector<uint8_t> ZKDevice::receiveRawData(size_t size) {
	std::vector<uint8_t> recevedData;
	if (verbose) std::cout << "[receiveRawData] Expecting " << size << " bytes raw data\n";

	while (size > 0) {
		auto chunk = sock.recv(size);
		size_t received = chunk.size();

		if (verbose) std::cout << "[receiveRawData] Partial recv: " << received << " bytes\n";

		if (received < 100 && verbose) {
			std::ostringstream oss;
			for (auto b : chunk)
				oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
			std::cout << "   recv: " << oss.str() << "\n";
		}

		recevedData.insert(recevedData.end(), chunk.begin(), chunk.end());
		size -= received;

		if (verbose) std::cout << "[receiveRawData] Still need: " << size << " bytes\n";
		if (verbose) std::cout << "[receiveRawData] Current recevedData.size(): " << recevedData.size() << "\n";
	}

	return recevedData;
}


std::vector<uint8_t> ZKDevice::receiveChunk() {
	std::vector<uint8_t> buffer;

	if (response == DeviceConstant::CMD_DATA) {
		if (tcp) {
			if (verbose) std::cout << "[receiveChunk] TCP CMD_DATA - data.size(): " << data.size() << ", tcpLength: " << tcpLength << "\n";
			if (data.size() < (tcpLength - 8)) {
				size_t need = (tcpLength - 8) - data.size();
				if (verbose) std::cout << "[receiveChunk] Need more data: " << need << "\n";
				auto more = receiveRawData(need);
				buffer = data;
				buffer.insert(buffer.end(), more.begin(), more.end());
				return buffer;
			}
			else {
				return data;
			}
		}
		else {
			if (verbose) std::cout << "[receiveChunk] Non-TCP CMD_DATA - data.size(): " << data.size() << "\n";
			return data;
		}
	}

	if (response == DeviceConstant::CMD_PREPARE_DATA) {
		int size = getDataSize();
		if (size <= 0) {
			if (verbose) std::cout << "[receiveChunk] Invalid data size: " << size << "\n";
			return {};
		}

		if (verbose) std::cout << "[receiveChunk] CMD_PREPARE_DATA - expected size: " << size << "\n";

		if (tcp) {
			std::vector<uint8_t> dataRecv;
			if (data.size() < 8) {
				if (verbose) std::cout << "[receiveChunk] Insufficient data for slicing\n";
				return {};
			}

			if (data.size() >= (8 + size)) {
				dataRecv.assign(data.begin() + 8, data.end());
			}
			else {
				auto more = sock.recv(size + 32);
				dataRecv.assign(data.begin() + 8, data.end());
				dataRecv.insert(dataRecv.end(), more.begin(), more.end());
			}

			auto [resp, brokenHeader] = receiveTcpData(dataRecv, size);
			buffer.insert(buffer.end(), resp.begin(), resp.end());

			std::vector<uint8_t> ackPacket;
			if (brokenHeader.size() < 16) {
				auto more = sock.recv(16 - brokenHeader.size());
				ackPacket = brokenHeader;
				ackPacket.insert(ackPacket.end(), more.begin(), more.end());
			}
			else {
				ackPacket = brokenHeader;
			}

			if (ackPacket.size() < 16 || !testTcpTop(ackPacket)) {
				if (verbose) std::cout << "[receiveChunk] Invalid TCP ACK packet\n";
				return {};
			}

			int ackResponse = Struct::unpack("<HHHH", { ackPacket.begin() + 8, ackPacket.begin() + 16 })[0].i;
			if (ackResponse == DeviceConstant::CMD_ACK_OK) {
				if (verbose) std::cout << "[receiveChunk] TCP ACK OK - returning buffer\n";
				return buffer;
			}

			if (verbose) std::cout << "[receiveChunk] Bad ACK response: " << ackResponse << "\n";
			return {};
		}

		while (true) {
			auto dataRecv = sock.recv(1032);
			if (dataRecv.size() < 8) {
				if (verbose) std::cout << "[receiveChunk] Packet too short - aborting\n";
				break;
			}

			int packetResponse = Struct::unpack("<4H", { dataRecv.begin(), dataRecv.begin() + 8 })[0].i;
			if (verbose) std::cout << "[receiveChunk] Packet response: " << packetResponse << "\n";

			if (packetResponse == DeviceConstant::CMD_DATA) {
				buffer.insert(buffer.end(), dataRecv.begin() + 8, dataRecv.end());
				size -= 1024;
			}
			else if (packetResponse == DeviceConstant::CMD_ACK_OK) {
				break;
			}
			else {
				if (verbose) std::cout << "[receiveChunk] Broken response - aborting\n";
				break;
			}

			if (verbose) std::cout << "[receiveChunk] Still needs: " << size << "\n";
		}

		return buffer;
	}

	if (verbose) std::cout << "[receiveChunk] Invalid response code: " << response << "\n";
	return {};
}


std::vector<User> ZKDevice::getUsers() {
	readSizes();
	if (users == 0) {
		nextUid = 1;
		nextUserId = "1";
		return {};
	}

	std::vector<User> userList;
	int maxUid = 0;

	auto [userdata, size] = readWithBuffer(DeviceConstant::CMD_USERTEMP_RRQ, DeviceConstant::FCT_USER);
	if (verbose) std::cout << "user size " << size << " (= " << userdata.size() << ")\n";
	if (size <= 4) {
		std::cout << "WRN: missing user data\n";
		return {};
	}

	int totalSize = Struct::unpack("<I", { userdata.begin(), userdata.begin() + 4 })[0].i;
	userPacketSize = totalSize / users;
	if (userPacketSize != 28 && userPacketSize != 72) {
		if (verbose) std::cout << "WRN packet size would be " << userPacketSize << "\n";
	}

	userdata.erase(userdata.begin(), userdata.begin() + 4);

	while (userdata.size() >= userPacketSize) {
		if (userPacketSize == 28) {
			auto fields = Struct::unpack("<HB5s8sIxBhI", { userdata.begin(), userdata.begin() + 28 });
			int uid = fields[0].i;
			int privilege = fields[1].i;
			std::string password = Struct::decodeString(fields[2].bytes, encoding);
			std::string name = Struct::decodeString(fields[3].bytes, encoding);
			uint32_t card = fields[4].i;
			std::string group_id = std::to_string(fields[6].i);
			std::string user_id = std::to_string(fields[8].i);

			if (uid > maxUid) maxUid = uid;
			if (name.empty()) name = "NN-" + user_id;

			userList.emplace_back(uid, name, privilege, password, group_id, user_id, card);
			if (verbose) std::cout << "[6]user: " << uid << " " << privilege << " " << password << " " << name << " " << card << " " << group_id << " " << user_id << "\n";
			userdata.erase(userdata.begin(), userdata.begin() + 28);
		}
		else {
			auto fields = Struct::unpack("<HB8s24sIx7sx24s", { userdata.begin(), userdata.begin() + 72 });
			int uid = fields[0].i;
			int privilege = fields[1].i;
			std::string password = Struct::decodeString(fields[2].bytes, encoding);
			std::string name = Struct::decodeString(fields[3].bytes, encoding);
			uint32_t card = fields[4].i;
			std::string group_id = Struct::decodeString(fields[5].bytes, encoding);
			std::string user_id = Struct::decodeString(fields[6].bytes, encoding);

			if (uid > maxUid) maxUid = uid;
			if (name.empty()) name = "NN-" + user_id;

			userList.emplace_back(uid, name, privilege, password, group_id, user_id, card);
			userdata.erase(userdata.begin(), userdata.begin() + 72);
		}
	}

	maxUid++;
	nextUid = maxUid;
	nextUserId = std::to_string(maxUid);

	while (std::any_of(userList.begin(), userList.end(), [&](const User& u) {
		return u.user_id == nextUserId;
		})) {
		maxUid++;
		nextUserId = std::to_string(maxUid);
	}

	return userList;
}

bool ZKDevice::cancelCapture() {
	auto cmdResponse = sendCommand(DeviceConstant::CMD_CANCELCAPTURE);
	return cmdResponse.status;
}

bool ZKDevice::verifyUser() {
	auto cmdResponse = sendCommand(DeviceConstant::CMD_STARTVERIFY);
	if (cmdResponse.status) return true;
	throw ZKErrorResponse("Can't Verify");
}

void ZKDevice::registerEvent(uint32_t flags) {
	auto commandString = Struct::pack("<I", {
		Struct::Value::fromInt(static_cast<int>(flags))
		});

	auto cmdResponse = sendCommand(DeviceConstant::CMD_REG_EVENT, commandString);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("can't reg events " + std::to_string(flags));
	}
}

bool ZKDevice::enrollUser(int uid, int tempId, const std::string& userIdInput) {
	uint32_t command = DeviceConstant::CMD_STARTENROLL;
	std::string userId = userIdInput;
	bool done = false;

	// Resolve userId if empty
	if (userId.empty()) {
		auto users = getUsers();
		auto it = std::find_if(users.begin(), users.end(), [&](const User& u) { return u.uid == uid; });
		if (it == users.end()) return false;
		userId = it->user_id;
	}

	// Prepare command payload
	std::vector<uint8_t> commandString;
	if (tcp) {
		std::vector<uint8_t> paddedUserId(userId.begin(), userId.end());
		paddedUserId.resize(24, 0);
		commandString = Struct::pack("<24sbb", {
			Struct::Value::fromBytes(paddedUserId),
			Struct::Value::fromInt(tempId),
			Struct::Value::fromInt(1)
			});
	}
	else {
		commandString = Struct::pack("<Ib", {
			Struct::Value::fromInt(std::stoi(userId)),
			Struct::Value::fromInt(tempId)
			});
	}

	cancelCapture();
	auto cmdResponse = sendCommand(command, commandString);
	if (!cmdResponse.status) {
		throw ZKErrorResponse("Can't enroll user #" + std::to_string(uid) + " [" + std::to_string(tempId) + "]");
	}

	sock.setTimeout(60);
	int attempts = 3;
	uint16_t res = 0;

	while (attempts-- > 0) {
		if (verbose) std::cout << "A:" << attempts + 1 << " waiting for first regevent\n";
		auto dataRecv = sock.recv(1032);
		ackOk();
		if (verbose) printHex(dataRecv);

		res = tcp && dataRecv.size() >= 18
			? Struct::unpack("<H", { dataRecv.begin() + 16, dataRecv.begin() + 18 })[0].i
			: Struct::unpack("<H", { dataRecv.begin() + 8, dataRecv.begin() + 10 })[0].i;

		if (verbose) std::cout << "res " << res << "\n";
		if (res == 6 || res == 4) {
			if (verbose) std::cout << "Timeout or registration failed\n";
			return false;
		}

		if (verbose) std::cout << "A:" << attempts + 1 << " waiting for 2nd regevent\n";
		dataRecv = sock.recv(1032);
		ackOk();
		if (verbose) printHex(dataRecv);

		res = tcp && dataRecv.size() >= 18
			? Struct::unpack("<H", { dataRecv.begin() + 16, dataRecv.begin() + 18 })[0].i
			: Struct::unpack("<H", { dataRecv.begin() + 8, dataRecv.begin() + 10 })[0].i;

		if (verbose) std::cout << "res " << res << "\n";
		if (res == 5) {
			if (verbose) std::cout << "Duplicate finger detected\n";
			return false;
		}
		if (res == 6 || res == 4) {
			if (verbose) std::cout << "Timeout or registration failed\n";
			return false;
		}
		if (res != 500) {
			if (verbose) std::cout << "Unexpected response during enrollment\n";
			return false;
		}
	}

	auto finalRecv = sock.recv(1032);
	ackOk();
	if (verbose) printHex(finalRecv);

	res = tcp && finalRecv.size() >= 18
		? Struct::unpack("<H", { finalRecv.begin() + 16, finalRecv.begin() + 18 })[0].i
		: Struct::unpack("<H", { finalRecv.begin() + 8, finalRecv.begin() + 10 })[0].i;

	if (verbose) std::cout << "Final res " << res << "\n";

	if (res == 0) {
		uint16_t size = Struct::unpack("<H", { finalRecv.begin() + 10, finalRecv.begin() + 12 })[0].i;
		uint16_t pos = Struct::unpack("<H", { finalRecv.begin() + 12, finalRecv.begin() + 14 })[0].i;
		if (verbose) std::cout << "Enrollment successful. Template size: " << size << ", Finger index: " << pos << "\n";
	}
	else if (res == 5) {
		if (verbose) std::cout << "Final check: Duplicate finger\n";
	}
	else {
		if (verbose) std::cout << "Final check: Enrollment failed or timed out\n";
	}

	// Cleanup only after verification
	sock.setTimeout(timeout);
	//if (done) {
		//if (verbose) std::cout << "Unregistering event...\n";
		//registerEvent(0);
		if (verbose) std::cout << "Cancelling capture...\n";
		cancelCapture();
		// Verify before finalizing
		if (verbose) std::cout << "Verifying enrolled fingerprint...\n";
		bool verified = verifyUser(); // You can pass uid or userId if needed

		if (verified) {
			if (verbose) std::cout << "Verification successful. Finalizing enrollment.\n";
			done = true;
		}
		else {
			if (verbose) std::cout << "Verification failed. Enrollment not finalized.\n";
			done = false;
		}
	//}

	if (verbose) std::cout << "Returning result to caller: " << done << "\n";
	return done;
}



void ZKDevice::printHex(const std::vector<uint8_t>& data) {
	std::ostringstream oss;
	for (auto b : data) {
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
	}
	std::cout << oss.str() << "\n";
}

std::vector<Attendance> ZKDevice::liveCapture(int newTimeout) {
	bool wasEnabled = isEnabled;
	auto users = getUsers();

	cancelCapture();
	verifyUser();
	if (!isEnabled) enableDevice();

	if (verbose) std::cout << "[liveCaptureBuffered] Starting capture\n";
	registerEvent(DeviceConstant::EF_ATTLOG);
	sock.setTimeout(newTimeout);
	endLiveCapture = false;

	std::vector<Attendance> events;

	while (!endLiveCapture) {
		try {
			auto dataRecv = sock.recv(1032);
			ackOk();

			std::vector<Struct::Value> header;
			std::vector<uint8_t> data;
			if (tcp) {
				header = Struct::unpack("<HHHH", { dataRecv.begin() + 8, dataRecv.begin() + 16 });
				data = std::vector<uint8_t>(dataRecv.begin() + 16, dataRecv.end());
			}
			else {
				header = Struct::unpack("<4H", { dataRecv.begin(), dataRecv.begin() + 8 });
				data = std::vector<uint8_t>(dataRecv.begin() + 8, dataRecv.end());
			}

			if (header[0].i != DeviceConstant::CMD_REG_EVENT || data.empty()) continue;

			while (data.size() >= 10) {
				std::string user_id;
				uint8_t status, punch;
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
				else if (data.size() == 14) {
					auto fields = Struct::unpack("<HBB6s4s", data);
					user_id = std::to_string(fields[0].i);
					status = fields[1].i;
					punch = fields[2].i;
					timehex = fields[3].bytes;
					chunkSize = 14;
				}
				else if (data.size() == 12) {
					auto fields = Struct::unpack("<IBB6s", data);
					user_id = std::to_string(fields[0].i);
					status = fields[1].i;
					punch = fields[2].i;
					timehex = fields[3].bytes;
					chunkSize = 12;
				}
				else if (data.size() == 10) {
					auto fields = Struct::unpack("<HBB6s", data);
					user_id = std::to_string(fields[0].i);
					status = fields[1].i;
					punch = fields[2].i;
					timehex = fields[3].bytes;
					chunkSize = 10;
				}
				else {
					break;
				}

				data.erase(data.begin(), data.begin() + chunkSize);
				auto timestamp = decodeTimeHex(timehex);
				int uid = 0;
				auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
					return u.user_id == user_id;
					});
				uid = (it != users.end()) ? it->uid : std::stoi(user_id);

				events.emplace_back(user_id, timestamp, status, punch, uid);
			}
		}
		catch (const std::exception& e) {
			if (verbose) std::cout << "[liveCaptureBuffered] Error: " << e.what() << "\n";
			break;
		}
	}

	sock.setTimeout(timeout);
	registerEvent(0);
	if (!wasEnabled) disableDevice();

	return events;
}

bool ZKDevice::clearData() {
	uint32_t command = DeviceConstant::CMD_CLEAR_DATA;
	std::vector<uint8_t> commandString;

	auto cmdResponse = sendCommand(command, commandString);
	if (cmdResponse.status) {
		nextUid = 1;
		return true;
	}
	else {
		throw ZKErrorResponse("can't clear data");
	}
}

std::vector<Attendance> ZKDevice::getAttendance() {
	readSizes();
	if (records == 0) return {};

	auto users = getUsers();
	if (verbose) std::cout << "User count: " << users.size() << "\n";

	std::vector<Attendance> attendances;
	auto [attendanceData, size] = readWithBuffer(DeviceConstant::CMD_ATTLOG_RRQ);
	if (size < 4) {
		if (verbose) std::cout << "WRN: no attendance data\n";
		return {};
	}

	int totalSize = Struct::unpack("<I", { attendanceData.begin(), attendanceData.begin() + 4 })[0].i;
	int recordSize = totalSize / records;
	if (verbose) std::cout << "record_size is " << recordSize << "\n";

	attendanceData.erase(attendanceData.begin(), attendanceData.begin() + 4);

	while (attendanceData.size() >= recordSize) {
		if (recordSize == 8) {
			auto fields = Struct::unpack("<HB4sB", { attendanceData.begin(), attendanceData.begin() + 8 });
			int uid = fields[0].i;
			int status = fields[1].i;
			auto timestamp = decodeTime(fields[2].bytes);
			int punch = fields[3].i;

			if (verbose) printHex({ attendanceData.begin(), attendanceData.begin() + 8 });
			attendanceData.erase(attendanceData.begin(), attendanceData.begin() + 8);

			std::string user_id = std::to_string(uid);
			auto it = std::find_if(users.begin(), users.end(), [&](const User& u) { return u.uid == uid; });
			if (it != users.end()) user_id = it->user_id;

			attendances.emplace_back(user_id, timestamp, status, punch, uid);
		}
		else if (recordSize == 16) {
			auto fields = Struct::unpack("<I4sBB2sI", { attendanceData.begin(), attendanceData.begin() + 16 });
			std::string user_id = std::to_string(fields[0].i);
			auto timestamp = decodeTime(fields[1].bytes);
			int status = fields[2].i;
			int punch = fields[3].i;

			if (verbose) printHex({ attendanceData.begin(), attendanceData.begin() + 16 });
			attendanceData.erase(attendanceData.begin(), attendanceData.begin() + 16);

			int uid = fields[0].i;
			auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
				return u.user_id == user_id || u.uid == uid;
				});
			if (it != users.end()) {
				uid = it->uid;
				user_id = it->user_id;
			}

			attendances.emplace_back(user_id, timestamp, status, punch, uid);
		}
		else {
			auto fields = Struct::unpack("<H24sB4sB8s", { attendanceData.begin(), attendanceData.begin() + 40 });
			int uid = fields[0].i;
			std::string user_id = Struct::decodeString(fields[1].bytes);
			auto timestamp = decodeTime(fields[3].bytes);
			int status = fields[2].i;
			int punch = fields[4].i;

			if (verbose) printHex({ attendanceData.begin(), attendanceData.begin() + 40 });
			attendanceData.erase(attendanceData.begin(), attendanceData.begin() + recordSize);

			attendances.emplace_back(user_id, timestamp, status, punch, uid);
		}
	}

	return attendances;
}

bool ZKDevice::clearAttendance() {
	auto cmdResponse = sendCommand(DeviceConstant::CMD_CLEAR_ATTLOG);
	if (cmdResponse.status) return true;
	throw ZKErrorResponse("Can't clear attendance");
}

std::vector<std::string> ZKDevice::split(const std::string& s, const std::string& delim) {
	std::vector<std::string> tokens;
	size_t start = 0, end;

	while ((end = s.find(delim, start)) != std::string::npos) {
		tokens.push_back(s.substr(start, end - start));
		start = end + delim.length();
	}
	tokens.push_back(s.substr(start));
	return tokens;
}











