CC	   = g++
CFLAGS = -g -Wall
OBJS   = main.o
TARGET = pcap_test

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap
	rm *.o

main.o: packet.h pcap_test.cpp

clean:
	rm -rf *.o $(TARGET)
