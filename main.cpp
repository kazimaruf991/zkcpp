#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include "zk/ZKDevice.hpp"
#include "zk/User.hpp"
#include "zk/Attendance.hpp"
#include "zk/ZKError.hpp"
#include "zk/LiveCaptureIterator.hpp"


void printAttendance(const std::vector<Attendance>& attendanceList) {
    if (attendanceList.empty()) {
        std::cout << "---- No attendance found! ----\n";
    }
    else {
        for (const auto& att : attendanceList) {
            std::cout << att << "\n";
        }
    }
}
std::string formatTimestamp(const std::tm& t) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
        t.tm_year, t.tm_mon, t.tm_mday,
        t.tm_hour, t.tm_min, t.tm_sec);
    return std::string(buffer);
}

int main() {
	std::string ip = ; //Add machine ip, eg.- "192.168.1.201"
    int port = 4307;
    int password = 0;

    ZKDevice zk(ip, port, 60, password);

    try {
        std::cout << "Connecting to device...\n";
        zk.connect();

        std::cout << "SDK build=1      : " << zk.setSdkBuild1() << "\n";
        std::cout << "Disabling device ...\n";
        zk.disableDevice();

        int fmt = zk.getExtendFmt();
        std::cout << "ExtendFmt        : " << fmt << "\n";
        fmt = zk.getUserExtendFmt();
        std::cout << "UsrExtFmt        : " << fmt << "\n";

        std::cout << "Face FunOn       : " << zk.getFaceFunOn() << "\n";
        std::cout << "Face Version     : " << zk.getFaceVersion() << "\n";
        std::cout << "Finger Version   : " << zk.getFpVersion() << "\n";
        std::cout << "Old Firm compat  : " << zk.getCompatOldFirmware() << "\n";

        auto net = zk.getNetworkParameters();
        if (!net.empty()) {
            std::cout << net << "\n";
        }
        else {
            std::cout << "Can't get network param from device\n";
        }

        auto machineTime = zk.getTime();
        std::cout << "Machine Time     : " << formatTimestamp(machineTime) << "\n";

        std::cout << "Firmware Version : " << zk.getFirmwareVersion() << "\n";
        std::cout << "Platform         : " << zk.getPlatform() << "\n";
        std::cout << "DeviceName       : " << zk.getDeviceName() << "\n";
        std::cout << "Pin Width        : " << zk.getPinWidth() << "\n";
        std::cout << "Serial Number    : " << zk.getSerialNumber() << "\n";
        std::cout << "MAC              : " << zk.getMacAddress() << "\n";

        std::cout << "\n--- sizes & capacity ---\n";
        zk.readSizes();
        std::cout << zk << "\n";


        std::cout << "\nGetting Users: ------------\n";
        auto start = std::chrono::steady_clock::now();
        auto users = zk.getUsers();
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        std::cout << "    took " << elapsed.count() << "[s]\n";

        if (users.empty()) {
            std::cout << "---- No user found! ----\n";
        }
        else {
            for (const auto& user : users) {
                std::cout << user << "\n";
            }
        }
        std::cout << "    took " << elapsed.count() << "[s]\n";
        std::cout << "---------------------------\n";

        
       std::cout << "Getting Attendance logs: ------------\n";
       start = std::chrono::steady_clock::now();
       auto attendance = zk.getAttendance();
       end = std::chrono::steady_clock::now();
       elapsed = end - start;
       std::cout << "    took " << elapsed.count() << "[s]\n";
       printAttendance(attendance);
       std::cout << "    took " << elapsed.count() << "[s]\n";
       std::cout << "---------------------------\n";
       


    /*
        
		std::cout << "Adding new uwer-------------------------------------------- - "<< std::endl;
        std::string name, admin, password, user_id, cardInput;
        int privilege = 0;
        int card = 0;
        int uid = zk.nextUid;

		std::cout << "UID        : " << uid << "\n";
        std::cout << "Name       : ";
        std::getline(std::cin, name);

        std::cout << "Admin (y/N): ";
        std::getline(std::cin, admin);
        privilege = (admin == "y" || admin == "Y") ? 14 : 0;

        std::cout << "Password   : ";
        std::getline(std::cin, password);

        std::cout << "User ID2   : ";
        std::getline(std::cin, user_id);

        std::cout << "Card       : ";
        std::getline(std::cin, cardInput);
        if (!cardInput.empty()) {
            std::stringstream ss(cardInput);
            ss >> card;
        }
		std::string group_id = "";
        try {
            zk.setUser(uid, name, privilege, password, group_id, user_id, card);
        }
        catch (const ZKErrorResponse& e) {
            std::cout << "error: " << e.what() << "\n";

            // Try new format
            User zk_user(uid, name, privilege, password, "", user_id, card);
            zk.saveUserTemplate(zk_user, {}); // forced creation
        }

        zk.refreshData();

		zk.nextUid++; // Increment nextUid after adding a user
		std::cout << "User added! Now Enrolling:......\n";

        zk.deleteUserTemplate(uid, 1);
        zk.registerEvent(USHRT_MAX);
        if (zk.enrollUser(uid, 1, user_id))
        {
			Finger finger;
            if (zk.getUserTemplate(uid, 1, user_id, finger)) {
				std::cout << "Finger enrolled: " << finger.dump() << "\n";
            }
            else
            {
				std::cout << "Can't read finger after enroll\n";
            }
        }
        else
        {
			std::cout << "Enroll failed\n";
        }

		zk.refreshData();

        std::cout << "----------------------------------------------------------- " << std::endl;

    */


    /*
        std::cout << "\n--- Live Capture! (press ctrl+C to break) ---\n";

        LiveCaptureIterator capture(zk, 10);  // 10-second timeout
        int counter = 0;

        while (true) {
            auto attOpt = capture.next();
            if (!attOpt.has_value()) {
                std::cout << "timeout " << counter << "\n";
            }
            else {
                const auto& att = attOpt.value();
                std::cout << "ATT " << std::setw(6) << counter
                    << ": uid:" << std::setw(3) << att.uid
                    << ", user_id:" << std::setw(8) << att.user_id
                    << " t: " << att.formatTimestamp(att.timestamp)
                    << ", s:" << att.status
                    << " p:" << att.punch << "\n";
            }

            counter++;
            if (counter >= 10) {
                zk.endLiveCapture = true;
                break;
            }
        }

        std::cout << "\n--- Capture End! ---\n";
    */



        std::cout << "Enabling device....\n";
        zk.enableDevice();
        zk.disconnect();
        std::cout << "Device disconnected!\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
