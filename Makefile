CC=gcc
CFLAGS=-g
BIN=miniftpd
OBJS=miniftp.o sysutil.o session.o ftpproto.o privparent.o str.o privsock.o tunable.o parseconf.o hash.o
LIBS=-lcrypt

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:clean
clean:
	rm -f *.o $(BIN)