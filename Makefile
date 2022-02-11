TARGET  := nfcapdu
WARN    := -Wall
CFLAGS  := -O2 ${WARN} `pkg-config --cflags libnfc`
LDFLAGS := `pkg-config --libs libnfc` -lreadline
CC      := gcc

C_SRCS    = $(wildcard *.c)
OBJ_FILES = $(C_SRCS:.c=.o)

all: ${TARGET}

%.o: %.c
	${CC} ${WARN} -c ${CFLAGS}  $< -o $@

${TARGET}: ${OBJ_FILES}
	${CC} ${WARN} ${LDFLAGS} -o $@  $(OBJ_FILES)

clean:
	rm -rf *.o ${TARGET}

mrproper: clean
	rm -rf *~
