CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS := -Os -s
CXXFLAGS += -w
COMPILED := dist
RM := rm

all: PoolPartyBof

PoolPartyBof:
	$(CC_x64) -o $(COMPILED)/PoolPartyBof_V8.x64.o -c src/Varient_8.c
	$(CC_x64) -o $(COMPILED)/PoolPartyBof_V7.x64.o -c src/Varient_7.c
	$(CC_x64) -o $(COMPILED)/PoolPartyBof_V6.x64.o -c src/Varient_6.c
	$(CC_x64) -o $(COMPILED)/PoolPartyBof_V5.x64.o -c src/Varient_5.c
	$(CC_x64) -o $(COMPILED)/PoolPartyBof_V4.x64.o -c src/Varient_4.c

clean:
	$(RM) $(COMPILED)/*.o
