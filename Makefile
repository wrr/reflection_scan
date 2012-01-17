CC       = g++
# DEBUG_FLAG = -g -DDEBUG
OPT_FLAG = -O2
CFLAGS = -Wall $(OPT_FLAG) $(DEBUG_FLAG)

all: send_query

send_query: send_query.cc
	$(CC) $(CFLAGS) send_query.cc -lnet -o send_query
