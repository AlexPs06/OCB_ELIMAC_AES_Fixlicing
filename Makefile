CC=g++
CFLAGS= -march=native 
LIB= -O3 -lgmp 
SOURCES= ELIMAC.c aes_encrypt.c aes_keyschedule_lut.c aes_keyschedule.c aes.h internal-aes.h
SOURCES2= OCBRA.c aes_encrypt.c aes_keyschedule_lut.c aes_keyschedule.c aes.h internal-aes.h
all: 
	$(CC) -o test1 $(SOURCES) $(LIB) $(CFLAGS) 
	$(CC) -o test2 $(SOURCES2) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 