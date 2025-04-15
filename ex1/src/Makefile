# Adjust this to your actual PIN installation path (full path, no ~)
PIN_ROOT = /home/ubuntu/Documents/pin-3.30-98830-g1d7b601b3-gcc-linux

TOOL_ROOT := .
TARGET := ex1
CXX := g++
CXXFLAGS := -Wall -Werror -Wno-unknown-pragmas -fPIC -O3 -std=c++11 \
	-I$(PIN_ROOT)/source/include/pin \
	-I$(PIN_ROOT)/source/include/pin/gen \
	-I$(PIN_ROOT)/extras/xed-intel64/include/xed \
	-I$(PIN_ROOT)/extras/components/include \
	-I$(PIN_ROOT)/extras/crt/include
LIBS := -shared

all: $(TARGET).so

$(TARGET).so: $(TARGET).o
	$(CXX) $(CXXFLAGS) $(LIBS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *.o *.so
