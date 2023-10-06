#include <stdio.h> 
#include "aes.h"
#include "internal-aes.h"

#define key_size 16

void print_array(uint8_t * plaintext, uint8_t size);

        
void divide_key(unsigned char* key, unsigned char * key0, unsigned char * key1);
void divide_plaintext(unsigned char* plaintext, unsigned char* ptext0,  unsigned char* ptext1,unsigned char plaintext_size);
void add_nonce(unsigned int * add_nonce, unsigned int * nonce, unsigned int size);
void xor_nonce(unsigned char * plaintext, unsigned char * nonce, unsigned int size);


void OCB(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* nonce, 
        unsigned char* asociated_data, unsigned char plaintext_size, unsigned char asociated_data_size,
        unsigned char* key, unsigned char* tag);
int main(){

    unsigned char key[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};
	unsigned char nonce[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};

    unsigned char tag[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char ciphertext[32]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0, 0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char plaintext[32]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0, 0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char asociated_data[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
    int plaintext_size = 32;
    int asociated_data_size = 0;

    // print_array(plaintext,16);

    // print_array(key,16);


    OCB(plaintext,  ciphertext,  nonce, asociated_data, plaintext_size, asociated_data_size, key, tag);

    // OCB(ctext0, ctext1, ptext0,  ptext1, key0,  key1);

    // print_array(ciphertext,16);
    // print_array(tag,16);


    return 0;
}




void OCB(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* nonce, 
        unsigned char* asociated_data, unsigned char plaintext_size, unsigned char asociated_data_size,
        unsigned char* key, unsigned char* tag){

    uint32_t size_ptext = (plaintext_size/2) + 16;
    uint32_t size = 0;

    if (plaintext_size%16 == 0 ){
        size = plaintext_size/16;
    }else{
        size = plaintext_size/16+1;
    }


    unsigned char ptext0[size_ptext];
    unsigned char ptext1[size_ptext];

    unsigned char ctext0[size_ptext];
    unsigned char ctext1[size_ptext];
    for (size_t i = 0; i < size_ptext; i++){
        ptext0[i]=0;
        ptext1[i]=0;
        ctext0[i]=0;
        ctext1[i]=0;
    }
    
    unsigned char key0[key_size];
    unsigned char key1[key_size];
    
    unsigned char key0_2AES[key_size*3] = {0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};
    // unsigned char key1_2AES[key_size*2] = {0,0,0,2, 0,0,0,2, 0,0,0,2 ,0,0,0,2, 0,0,0,3, 0,0,0,3, 0,0,0,3 ,0,0,0,3};

    unsigned char N_0[16];
    unsigned char N_1[16];

    unsigned char c_N_0[16];
    unsigned char c_N_1[16];
    unsigned char checksum[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    unsigned int add_nonce_0[4] = {0,0,0,0};
    unsigned int add_nonce_1[4] = {1,1,1,1};

    unsigned int add_nonce_2[4] = {2,2,2,2};
    
    divide_plaintext(plaintext, ptext0,  ptext1, plaintext_size);
    divide_key(key, key0, key1);

	uint32_t rkeys_ffs[88];
    uint32_t two_AES_keys_ffs[64];

	aes128_keyschedule_ffs(rkeys_ffs, key0, key1);
    

    // print_array((unsigned char *) &rkeys_ffs , 16 );

    // print_array(nonce,16);
    // print_array((unsigned char *)rkeys_ffs+0,16 );
	aes128_encrypt_ffs(N_0, N_1, nonce, nonce, rkeys_ffs);
    
    // print_array(N_0,16);

    
    // aes128_2rounds_keyschedule_ffs(two_AES_keys_ffs, key0_2AES, rkeys_ffs);

    for (size_t i = 0; i < size/2; i++){

        add_nonce(add_nonce_0, (unsigned int *)N_0, 4);
        add_nonce(add_nonce_1, (unsigned int *)N_1, 4);


        // print_array(N_0,16);
        // print_array(N_1,16);

        two_Rounds_aes128_encrypt_ffs(c_N_0,  c_N_1, N_0,  N_1, rkeys_ffs);
        
       

        xor_nonce( checksum, ptext0 + (i*16), 16);
        xor_nonce( checksum, ptext1 + (i*16), 16);

        xor_nonce( ptext0+  (i*16), c_N_0, 16);
        xor_nonce( ptext1 + (i*16), c_N_1, 16);

         print_array(ptext0,16);
        print_array(ptext1,16);
	    aes128_encrypt_ffs(ctext0+ (i*16), ctext1+ (i*16), ptext0+ ((i)*16), ptext1 + (i*16), rkeys_ffs);

        xor_nonce( ctext0+ ( i*16), c_N_0, 16);
        // xor_nonce( ctext1 + (i*16), c_N_1, 16);


        print_array(ctext0,16);
        print_array(ctext1,16);

        // add_nonce(add_nonce_2, add_nonce_0, 4);
        // add_nonce(add_nonce_2, add_nonce_1, 4);
        
    }
    
   
    

    // seven_Rounds_aes128_encrypt_ffs(ctext0, ctext1, ptext0, ptext1, rkeys_ffs);
	// // aes128_encrypt_ffs(ctext0, ctext1, ptext0, ptext1, rkeys_ffs);

}
void add_nonce(unsigned int * add_nonce, unsigned int * nonce, unsigned int size){
    for (size_t i = 0; i < size; i++){
        nonce[i]=nonce[i]+ add_nonce[i];
    }
    
}

void xor_nonce(unsigned char * plaintext, unsigned char * nonce, unsigned int size){
    for (size_t i = 0; i < size; i++){
        plaintext[i]=nonce[i]^ plaintext[i];
    }
    
}
void divide_plaintext(unsigned char* plaintext, unsigned char* ptext0,  unsigned char* ptext1,unsigned char plaintext_size){

    uint32_t size = 0;

    if (plaintext_size%16 == 0 ){
        size = plaintext_size/16;
    }else{
        size = plaintext_size/16+1;
    }

    bool condicion = 1;
    size_t j=0;
    size_t k=0;
    for (size_t i = 0; i < plaintext_size; i++){
        
        if (condicion)
            ptext0[j] = plaintext[i];
        else
            ptext1[k] = plaintext[i];
        
        if (i%16==0 && i!=0)
            condicion=condicion^1;
        
        if (condicion)
            j++;
        else
            k++;
        
    }
}

void divide_key(unsigned char* key, unsigned char * key0, unsigned char * key1){

    for (size_t i = 0; i < key_size; i++){
        key0[i] = key[i];
        key1[i] = key[i];
    }
}


void print_array(uint8_t * plaintext, uint8_t size){
    for (size_t i = 0; i < size; i++){
        printf("%02x ", plaintext[i]);
    }
    printf("\n");
}
