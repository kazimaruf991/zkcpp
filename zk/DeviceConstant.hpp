#pragma once

#include <cstdint>

class DeviceConstant {
public:
    // Command codes
    static constexpr uint16_t CMD_DB_RRQ = 7;
    static constexpr uint16_t CMD_USER_WRQ = 8;
    static constexpr uint16_t CMD_USERTEMP_RRQ = 9;
    static constexpr uint16_t CMD_USERTEMP_WRQ = 10;
    static constexpr uint16_t CMD_OPTIONS_RRQ = 11;
    static constexpr uint16_t CMD_OPTIONS_WRQ = 12;
    static constexpr uint16_t CMD_ATTLOG_RRQ = 13;
    static constexpr uint16_t CMD_CLEAR_DATA = 14;
    static constexpr uint16_t CMD_CLEAR_ATTLOG = 15;
    static constexpr uint16_t CMD_DELETE_USER = 18;
    static constexpr uint16_t CMD_DELETE_USERTEMP = 19;
    static constexpr uint16_t CMD_CLEAR_ADMIN = 20;
    static constexpr uint16_t CMD_USERGRP_RRQ = 21;
    static constexpr uint16_t CMD_USERGRP_WRQ = 22;
    static constexpr uint16_t CMD_USERTZ_RRQ = 23;
    static constexpr uint16_t CMD_USERTZ_WRQ = 24;
    static constexpr uint16_t CMD_GRPTZ_RRQ = 25;
    static constexpr uint16_t CMD_GRPTZ_WRQ = 26;
    static constexpr uint16_t CMD_TZ_RRQ = 27;
    static constexpr uint16_t CMD_TZ_WRQ = 28;
    static constexpr uint16_t CMD_ULG_RRQ = 29;
    static constexpr uint16_t CMD_ULG_WRQ = 30;
    static constexpr uint16_t CMD_UNLOCK = 31;
    static constexpr uint16_t CMD_CLEAR_ACC = 32;
    static constexpr uint16_t CMD_CLEAR_OPLOG = 33;
    static constexpr uint16_t CMD_OPLOG_RRQ = 34;
    static constexpr uint16_t CMD_GET_FREE_SIZES = 50;
    static constexpr uint16_t CMD_ENABLE_CLOCK = 57;
    static constexpr uint16_t CMD_STARTVERIFY = 60;
    static constexpr uint16_t CMD_STARTENROLL = 61;
    static constexpr uint16_t CMD_CANCELCAPTURE = 62;
    static constexpr uint16_t CMD_STATE_RRQ = 64;
    static constexpr uint16_t CMD_WRITE_LCD = 66;
    static constexpr uint16_t CMD_CLEAR_LCD = 67;
    static constexpr uint16_t CMD_GET_PINWIDTH = 69;
    static constexpr uint16_t CMD_SMS_WRQ = 70;
    static constexpr uint16_t CMD_SMS_RRQ = 71;
    static constexpr uint16_t CMD_DELETE_SMS = 72;
    static constexpr uint16_t CMD_UDATA_WRQ = 73;
    static constexpr uint16_t CMD_DELETE_UDATA = 74;
    static constexpr uint16_t CMD_DOORSTATE_RRQ = 75;
    static constexpr uint16_t CMD_WRITE_MIFARE = 76;
    static constexpr uint16_t CMD_EMPTY_MIFARE = 78;
    static constexpr uint16_t _CMD_GET_USERTEMP = 88;
    static constexpr uint16_t _CMD_SAVE_USERTEMPS = 110;
    static constexpr uint16_t _CMD_DEL_USER_TEMP = 134;

    static constexpr uint16_t CMD_GET_TIME = 201;
    static constexpr uint16_t CMD_SET_TIME = 202;
    static constexpr uint16_t CMD_REG_EVENT = 500;

    static constexpr uint16_t CMD_CONNECT = 1000;
    static constexpr uint16_t CMD_EXIT = 1001;
    static constexpr uint16_t CMD_ENABLEDEVICE = 1002;
    static constexpr uint16_t CMD_DISABLEDEVICE = 1003;
    static constexpr uint16_t CMD_RESTART = 1004;
    static constexpr uint16_t CMD_POWEROFF = 1005;
    static constexpr uint16_t CMD_SLEEP = 1006;
    static constexpr uint16_t CMD_RESUME = 1007;
    static constexpr uint16_t CMD_CAPTUREFINGER = 1009;
    static constexpr uint16_t CMD_TEST_TEMP = 1011;
    static constexpr uint16_t CMD_CAPTUREIMAGE = 1012;
    static constexpr uint16_t CMD_REFRESHDATA = 1013;
    static constexpr uint16_t CMD_REFRESHOPTION = 1014;
    static constexpr uint16_t CMD_TESTVOICE = 1017;
    static constexpr uint16_t CMD_GET_VERSION = 1100;
    static constexpr uint16_t CMD_CHANGE_SPEED = 1101;
    static constexpr uint16_t CMD_AUTH = 1102;
    static constexpr uint16_t CMD_PREPARE_DATA = 1500;
    static constexpr uint16_t CMD_DATA = 1501;
    static constexpr uint16_t CMD_FREE_DATA = 1502;
    static constexpr uint16_t _CMD_PREPARE_BUFFER = 1503;
    static constexpr uint16_t _CMD_READ_BUFFER = 1504;

    static constexpr uint16_t CMD_ACK_OK = 2000;
    static constexpr uint16_t CMD_ACK_ERROR = 2001;
    static constexpr uint16_t CMD_ACK_DATA = 2002;
    static constexpr uint16_t CMD_ACK_RETRY = 2003;
    static constexpr uint16_t CMD_ACK_REPEAT = 2004;
    static constexpr uint16_t CMD_ACK_UNAUTH = 2005;

    static constexpr uint16_t CMD_ACK_UNKNOWN = 0xffff;
    static constexpr uint16_t CMD_ACK_ERROR_CMD = 0xfffd;
    static constexpr uint16_t CMD_ACK_ERROR_INIT = 0xfffc;
    static constexpr uint16_t CMD_ACK_ERROR_DATA = 0xfffb;

    // Event flags
    static constexpr uint16_t EF_ATTLOG = 1;
    static constexpr uint16_t EF_FINGER = (1 << 1);
    static constexpr uint16_t EF_ENROLLUSER = (1 << 2);
    static constexpr uint16_t EF_ENROLLFINGER = (1 << 3);
    static constexpr uint16_t EF_BUTTON = (1 << 4);
    static constexpr uint16_t EF_UNLOCK = (1 << 5);
    static constexpr uint16_t EF_VERIFY = (1 << 7);
    static constexpr uint16_t EF_FPFTR = (1 << 8);
    static constexpr uint16_t EF_ALARM = (1 << 9);

    // User roles
    static constexpr uint16_t USER_DEFAULT = 0;
    static constexpr uint16_t USER_ENROLLER = 2;
    static constexpr uint16_t USER_MANAGER = 6;
    static constexpr uint16_t USER_ADMIN = 14;

    // Function types
    static constexpr uint16_t FCT_ATTLOG = 1;
    static constexpr uint16_t FCT_WORKCODE = 8;
    static constexpr uint16_t FCT_FINGERTMP = 2;
    static constexpr uint16_t FCT_OPLOG = 4;
    static constexpr uint16_t FCT_USER = 5;
    static constexpr uint16_t FCT_SMS = 6;
    static constexpr uint16_t FCT_UDATA = 7;

    // Machine constants
    static constexpr uint16_t MACHINE_PREPARE_DATA_1 = 20560;
    static constexpr uint16_t MACHINE_PREPARE_DATA_2 = 32130;
};
