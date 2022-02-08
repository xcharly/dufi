BIN_NAME = dufi.elf

CFLAGS = -fPIC -O0 -g -Wall
LFLAGS = 

SRC_FILES = dufi.c

default: all

all: $(BIN_NAME)

$(BIN_NAME): $(patsubst %.c, %.o, $(SRC_FILES))
	$(CROSS_CC) -o $@ $^

%.o: %.c
	$(CROSS_CC) $(LFLAGS) -c $(CFLAGS) -o $@ $<

clean: 
	rm *.o
	rm *.elf