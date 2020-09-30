
CC=gcc
DES=des

$(DES): des.o main.o
	${CC} ${CCFLAGS} -Iinclude $^ -o $@

%.o: %.c
	${CC} ${CCFLAGS} -Iinclude -o $@ -c $^

clean:
	rm -f $(DES) *.o