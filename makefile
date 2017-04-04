simple: simple.o easyssl.o easyssl.h
	cc -o simple simple.o easyssl.o -lssl
clean:
	rm -f simple simple.o easyssl.o 
