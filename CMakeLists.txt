cmake_minimum_required(VERSION 3.10)
project(pcap-parser C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wall -Wextra -O2 -Iinclude")

set(SRC src/main.c src/pcap.c src/ethernet.c src/ip.c src/tcp.c src/http.c)

add_executable(pcap-parser ${SRC})