#include <stdio.h>
#include "lib/pcap-master.h"


int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }
}
