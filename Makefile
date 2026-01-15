CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

CFLAGS := -c -Os -s -DNDEBUG
CFLAGS_x64 := $(CFLAGS) -m64
CFLAGS_x86 := $(CFLAGS) -m32

.PHONY: all clean x64 x86

all: x64 x86

x64: prefetch.x64.o

x86: prefetch.x86.o

prefetch.x64.o: prefetch_bof.c
	$(CC_x64) $(CFLAGS_x64) prefetch_bof.c -o prefetch.x64.o

prefetch.x86.o: prefetch_bof.c
	$(CC_x86) $(CFLAGS_x86) prefetch_bof.c -o prefetch.x86.o

clean:
	rm -f *.o
