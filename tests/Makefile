CFLAGS=-mclwb -mclflushopt -Wall -pthread -DBITS_PER_LONG=64
CDEBUG=-g
CRELEASE=-O3

test: 
	gcc $(CFLAGS) $(CDEBUG) test.c -o test

clean:
	rm -f test