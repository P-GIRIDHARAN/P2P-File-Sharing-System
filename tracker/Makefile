CXX = g++
CXXFLAGS = -Wall -pthread -std=c++17
LDFLAGS = -lcrypto 

TARGET = tracker
SRCS = tracker.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)