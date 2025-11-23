CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude

SRC = src/main.c src/pcap.c src/ethernet.c # src/protocol/ethernet.c src/protocol/ipv4.c
OBJ = $(SRC:.c=.o)

all: pcap-parser

pcap-parser: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

clean:
	rm -f $(OBJ) pcap-parser
