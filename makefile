
simple: simple.c easyssl.o easyssl.h
	cc -o simple simple.c easyssl.o -lssl

easyssl.o: easyssl.c easyssl.h

clean:
	rm -f simple easyssl.o 
