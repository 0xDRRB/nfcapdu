TARGET  := nfcapdu
WARN    := -Wall
#DEBUG	:= -g
CFLAGS  := -O2 $(DEBUG) ${WARN} `pkg-config --cflags libnfc glib-2.0`
LDFLAGS := `pkg-config --libs libnfc glib-2.0`  -lreadline
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
