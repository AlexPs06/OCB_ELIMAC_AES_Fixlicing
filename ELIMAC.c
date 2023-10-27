#include <stdio.h> 
#include "aes.h"
#include "internal-aes.h"

#define key_size 16
#define bit_size 16

void print_array(uint8_t * plaintext, uint8_t size);

        
void divide_key(unsigned char* key, unsigned char * key0, unsigned char * key1);
void divide_plaintext(unsigned char* plaintext, unsigned char* ptext0,  unsigned char* ptext1,unsigned int plaintext_size);
void add_nonce(unsigned int * add_nonce, unsigned int * nonce, unsigned int * nonce_result, unsigned int size);
void xor_nonce(unsigned char * plaintext, unsigned char * nonce, unsigned int size);
void ELIMAC(unsigned char* plaintext,  unsigned char plaintext_size, unsigned char* key1, unsigned char* key2, unsigned char rounds, unsigned char* tag);
void H(unsigned char* ptext0,  unsigned char *ptext1, uint32_t* rkeys_ffs_H, unsigned char rounds);
void I(unsigned char* ptext0,  unsigned char *ptext1, uint32_t* rkeys_ffs_H, unsigned char rounds);
int main(){

    const int plaintext_size = 32;

    unsigned char key1[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};
    unsigned char key2[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};
	unsigned char nonce[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};

    unsigned char tag[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char plaintext[plaintext_size]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
    
    for (size_t i = 0; i < plaintext_size; i++)
    {
        plaintext[i] =i;
    }
    


    ELIMAC( plaintext,  plaintext_size,  key1,  key2, 4,  tag);

    // OCB(ctext0, ctext1, ptext0,  ptext1, key0,  key1);

    // print_array(ciphertext,16);
    print_array(tag,16);


    return 0;
}




void ELIMAC(unsigned char* plaintext,  const unsigned char plaintext_size, unsigned char* key1, unsigned char* key2, unsigned char rounds, unsigned char* tag){

    unsigned char ptext0[plaintext_size];
    unsigned char ptext1[plaintext_size];


    unsigned char i_n1[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    unsigned char i_n2[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};


    unsigned char S1[bit_size];
    unsigned char S2[bit_size];
    
    unsigned int add_nonce_0[4] = {0,0,0,0};
    unsigned int add_nonce_1[4] = {1,1,1,1};
    unsigned int add_nonce_2[4] = {2,2,2,2};


    uint32_t rkeys_ffs[88];
    uint32_t rkeys_ffs_zeros[88];
    uint32_t rkeys_ffs_H[88];

    for (size_t i = 0; i < plaintext_size; i++)
    {
        ptext1[i]=0;
        ptext0[i]=0;
    }    

    divide_plaintext(plaintext, ptext0, ptext1, plaintext_size);
    
    for (size_t i = 0; i < bit_size; i++)
    {
        S1[i]=0;
        S2[i]=0;
    }    

    for (size_t i = 0; i < 88; i++)
    {
        rkeys_ffs_zeros[i]=0;
    }

    aes128_keyschedule_ffs(rkeys_ffs_H, key1, key1);
    aes128_keyschedule_ffs(rkeys_ffs, key2, key2);

    int block_size = plaintext_size/32;

    for (int i = 0; i < block_size; i++){

        add_nonce(add_nonce_0, (unsigned int *)i_n1,(unsigned int *)i_n1, 4);
        add_nonce(add_nonce_1, (unsigned int *)i_n2,(unsigned int *)i_n2, 4);

        H(i_n1, i_n2, rkeys_ffs_H, rounds);

        xor_nonce( ptext0+ (i*16), i_n1, 16);
        xor_nonce( ptext1+ (i*16), i_n2, 16);

        I(ptext0,  ptext1, rkeys_ffs, 4);

        xor_nonce( S1,ptext0+ (i*16), 16);
        xor_nonce( S2,ptext1+ (i*16), 16);

        add_nonce(add_nonce_2, add_nonce_0,add_nonce_0, 4);
        add_nonce(add_nonce_2, add_nonce_1,add_nonce_1, 4);
    }
    
    xor_nonce( S1,S2, 16);

    aes128_encrypt_ffs(tag, S2, S1,S1, rkeys_ffs);

}

void H(unsigned char* ptext0,  unsigned char *ptext1, uint32_t *rkeys_ffs_H, unsigned char rounds){

    switch (rounds)
    {
    case 2:
        two_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    case 4:
        four_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    case 6:
        six_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    case 8:
        eigth_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    
    default:
        break;
    }

}

void I(unsigned char* ptext0,  unsigned char *ptext1, uint32_t *rkeys_ffs_H, unsigned char rounds){

    switch (rounds)
    {
    case 2:
        two_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    case 4:
        four_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    case 6:
        six_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    case 8:
        eigth_Rounds_aes128_encrypt_ffs(ptext0, ptext1, ptext0, ptext1, rkeys_ffs_H);
        break;
    
    default:
        break;
    }

}

void add_nonce(unsigned int * add_nonce, unsigned int * nonce, unsigned int * nonce_result, unsigned int size){
    for (size_t i = 0; i < size; i++){
        nonce_result[i]=nonce[i]+ add_nonce[i];
    }
    
}

void xor_nonce(unsigned char * plaintext, unsigned char * nonce, unsigned int size){
    for (size_t i = 0; i < size; i++){
        plaintext[i]=nonce[i]^ plaintext[i];
    }
    
}
void divide_plaintext(unsigned char* plaintext, unsigned char* ptext0,  unsigned char* ptext1,unsigned int plaintext_size){
    int condicion = 1;
    size_t j=0;
    size_t k=0;
    for (size_t i = 0; i < plaintext_size; i++){
        
        if (i%16==0 && i!=0)
            condicion=condicion^1;

        if (condicion)
            ptext0[j] = plaintext[i];
        else
            ptext1[k] = plaintext[i];
        
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
