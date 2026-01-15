CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

CFLAGS := -c -Os -s -DNDEBUG
CFLAGS_x64 := $(CFLAGS) -m64
CFLAGS_x86 := $(CFLAGS) -m32

.PHONY: all clean x64 x86

all: x64 x86

x64: portscanner.x64.o

x86: portscanner.x86.o

portscanner.x64.o: portscanner_bof.c beacon.h
	$(CC_x64) $(CFLAGS_x64) portscanner_bof.c -o portscanner.x64.o

portscanner.x86.o: portscanner_bof.c beacon.h
	$(CC_x86) $(CFLAGS_x86) portscanner_bof.c -o portscanner.x86.o

clean:
	rm -f *.o
