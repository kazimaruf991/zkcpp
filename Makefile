CXX = clang++
CXXFLAGS = -Wall -O2 -Iinclude -Izk
MAIN = main.cpp
SRC = $(wildcard zk/*.cpp)
BUILD_DIR = build
OUTPUT_DIR = $(BUILD_DIR)/output
OUT = $(OUTPUT_DIR)/zkapp

all: $(BUILD_DIR) $(OUTPUT_DIR)
	$(CXX) $(CXXFLAGS) $(MAIN) $(SRC) -o $(OUT)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

clean:
	rm -rf $(BUILD_DIR)
