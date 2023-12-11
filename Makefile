CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS := -Os -s
CXXFLAGS += -w
COMPILED := dist
RM := rm

all: PoolPartyBof

PoolPartyBof:
	$(CC_x64) -o $(COMPILED)/PoolPartyBof.x64.o -c src/PoolPartyBof.c

clean:
	$(RM) $(COMPILED)/*.o
