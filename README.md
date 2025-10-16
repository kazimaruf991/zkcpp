# zkcpp — C++ Port of pyzk for ZKTeco Devices

zkcpp is a C++ library that ports the core functionality of the [pyzk](https://github.com/fananimi/pyzk) Python project to native C++.

---

## ⚙️ Environment Setup

### ▶️ Termux (Android)

```bash
pkg update
pkg install clang make cmake git
```
---

### 🐧 Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install clang make cmake git
```
---

## 🛠️ Build & Run

```bash
git clone https://github.com/yourname/zkcpp.git
cd zkcpp
make
./build/output/zkapp
```
⚠️ Before building, open [`main.cpp`](main.cpp) and set your device's IP address, port & password:

```cpp
std::string ip = ; // Add machine IP, e.g. "192.168.1.201"
int port = 4370;
int password = 0;
```

---

📄 Check [`main.cpp`](main.cpp) for example usage and basic interaction flow with the device. It demonstrates how to connect, disable/enable the device, and fetch logs.
