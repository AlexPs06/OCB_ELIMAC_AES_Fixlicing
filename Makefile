CC=g++
CFLAGS= -march=native 
LIB= -O3 -lgmp 
SOURCES= OCBRA.c aes_encrypt.c aes_keyschedule_lut.c aes_keyschedule.c aes.h internal-aes.h
all: 
	$(CC) -o test $(SOURCES) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 