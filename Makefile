CXX := g++
CXXFLAGS := -O2 -std=gnu++20 -Wall -Wextra -I./ -Ithird_party
LIBS := -lssl -lcrypto -lqrencode -lpng -lpthread -lZXing
BIN := build
ENC := $(BIN)/encode
DEC := $(BIN)/decode
all: $(ENC) $(DEC)
$(ENC): src/encode.cpp src/common.hpp third_party/json.hpp
	@mkdir -p $(BIN)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LIBS)
$(DEC): src/decode.cpp src/common.hpp third_party/json.hpp
	@mkdir -p $(BIN)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LIBS)
clean: ; rm -rf $(BIN)
.PHONY: all clean
