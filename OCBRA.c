#include <stdio.h> 
#include "aes.h"
#include "internal-aes.h"

#define key_size 16

void print_array(uint8_t * plaintext, uint32_t size);

        
void divide_key(unsigned char* key, unsigned char * key0, unsigned char * key1);
void divide_plaintext(unsigned char* plaintext, unsigned char* ptext0,  unsigned char* ptext1,unsigned int plaintext_size);
void add_nonce(unsigned int * add_nonce, unsigned int * nonce, unsigned int * nonce_result, unsigned int size);
void xor_nonce(unsigned char * plaintext, unsigned char * nonce, unsigned int size);
void union_ciphertext(unsigned char* ciphertext, unsigned char* ctext0,  unsigned char* ctext1,unsigned int plaintext_size);
void PMAC( unsigned char* nonce, unsigned char* asociated_data, unsigned int asociated_data_size, unsigned char* key, unsigned char* tag);
void OCB(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* nonce,unsigned char* asociated_data, unsigned int plaintext_size, unsigned int asociated_data_size,unsigned char* key, unsigned char* tag);
int main(){

    const int plaintext_size = 4096;
    const int asociated_data_size = 4096;

    unsigned char key[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};
	unsigned char nonce[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};

    unsigned char tag[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char ciphertext[plaintext_size+16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char plaintext[plaintext_size+16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char asociated_data[asociated_data_size+16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
    

    for (size_t i = 0; i < plaintext_size; i++)
    {
        ciphertext[i]=0;
        plaintext[i] =i;
    }
    for (size_t i = 0; i < asociated_data_size; i++)
    {
        asociated_data[i]=i;
    }

    
    

	// uint32_t rkeys_ffs[88];
	// aes128_keyschedule_ffs(rkeys_ffs, key, key);
    // print_array(key,16);

    // printf("----------------2rounds-----------------\n");
    // print_array(ptext0,16);
    // two_Rounds_aes128_encrypt_ffs(ctext0,  ctext1, ptext0,  ptext1, rkeys_ffs);
    // print_array(ctext0,16);
    // for (size_t i = 0; i < 16; i++)
    // {
    //     ptext0[i]= i;
    //     ptext1[i]= i;
    //     ctext0[i]= 0;
    //     ctext1[i]= 0;
    // }
    // printf("----------------4rounds-----------------\n");
    // print_array(ptext0,16);
    // four_Rounds_aes128_encrypt_ffs(ctext0,  ctext1, ptext0,  ptext1, rkeys_ffs);
    // print_array(ctext0,16);
    
    // for (size_t i = 0; i < 16; i++)
    // {
    //     ptext0[i]= i;
    //     ptext1[i]= i;
    //     ctext0[i]= 0;
    //     ctext1[i]= 0;
    // }
    // printf("----------------6rounds-----------------\n");
    // print_array(ptext0,16);
    // six_Rounds_aes128_encrypt_ffs(ctext0,  ctext1, ptext0,  ptext1, rkeys_ffs);
    // print_array(ctext0,16);
    
    // for (size_t i = 0; i < 16; i++)
    // {
    //     ptext0[i]= i;
    //     ptext1[i]= i;
    //     ctext0[i]= 0;
    //     ctext1[i]= 0;
    // }
    // printf("----------------8rounds-----------------\n");
    // print_array(ptext0,16);
    // eigth_Rounds_aes128_encrypt_ffs(ctext0,  ctext1, ptext0,  ptext1, rkeys_ffs);
    // print_array(ctext0,16);
    
    // divide_plaintext(plaintext, ptext0,  ptext1, plaintext_size);
    
    printf("----------------Plaintext-----------------\n");
    print_array(plaintext,plaintext_size);
    printf("----------------Key-----------------\n");
    print_array(key,16);

    OCB(plaintext,  ciphertext,  nonce, asociated_data, plaintext_size, asociated_data_size, key, tag);

    printf("----------------ciphertext-----------------\n");
    print_array(ciphertext,plaintext_size);
    printf("----------------TAG-----------------\n");
    print_array(tag,16);

    return 0;
}




void OCB(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* nonce, 
        unsigned char* asociated_data, unsigned int plaintext_size, unsigned int asociated_data_size,
        unsigned char* key, unsigned char* tag){
        



    if (asociated_data_size!=0)
    {
        PMAC(nonce,asociated_data,asociated_data_size,key,tag);

    }
    

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
    
    unsigned char key_2AES[key_size] = {0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3};

    unsigned char N_0[16];
    unsigned char N_1[16];

    unsigned char N_0_t[16];
    unsigned char N_1_t[16];

    unsigned char c_N_0[16];
    unsigned char c_N_1[16];
    unsigned char checksum[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char S[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    unsigned int add_nonce_0[4] = {0,0,0,0};
    unsigned int add_nonce_1[4] = {1,1,1,1};

    unsigned int add_nonce_2[4] = {2,2,2,2};
    
    divide_plaintext(plaintext, ptext0,  ptext1, plaintext_size);
    divide_key(key, key0, key1);

    //key schedule
	uint32_t rkeys_ffs[88];
    uint32_t two_AES_keys_ffs[88];

	aes128_keyschedule_ffs(rkeys_ffs, key0, key1);
    aes128_2rounds_keyschedule_ffs(two_AES_keys_ffs, key_2AES, key_2AES);

	//generate the N from nonce using 10 aes rounds
    aes128_encrypt_ffs(N_0, N_1, nonce, nonce, rkeys_ffs);

    for (size_t i = 0; i < size/2; i++){

        add_nonce(add_nonce_0, (unsigned int *)N_0,(unsigned int *)N_0_t, 4);
        add_nonce(add_nonce_1, (unsigned int *)N_1,(unsigned int *)N_1_t, 4);

        two_Rounds_aes128_encrypt_ffs(c_N_0,  c_N_1, N_0_t,  N_1_t, two_AES_keys_ffs);

        // print_array(ptext0+ (i*16),16);
        // print_array(ptext1+ (i*16),16);

        xor_nonce( checksum, ptext0 + (i*16), 16);
        xor_nonce( checksum, ptext1 + (i*16), 16);

        xor_nonce( ptext0 +  (i*16), c_N_0, 16);
        xor_nonce( ptext1 + (i*16), c_N_1, 16);




	    aes128_encrypt_ffs(ctext0+ (i*16), ctext1+ (i*16), ptext0+ ((i)*16), ptext1 + (i*16), rkeys_ffs);
        xor_nonce( ctext0 + (i*16), c_N_0, 16);
        xor_nonce( ctext1 + (i*16), c_N_1, 16);
        
        // print_array(ctext0+ (i*16),16);
        // print_array(ctext1+ (i*16),16);

        add_nonce(add_nonce_2, add_nonce_0,add_nonce_0, 4);
        add_nonce(add_nonce_2, add_nonce_1,add_nonce_1, 4);
        
    }
    
    union_ciphertext(ciphertext,ctext0,ctext1,plaintext_size);

    if (1)//condicion de bloques completos
    {
        add_nonce(add_nonce_1, (unsigned int *)N_0,(unsigned int *)N_0_t, 4);
        two_Rounds_aes128_encrypt_ffs(c_N_0,  c_N_1, N_0_t,  N_0_t, two_AES_keys_ffs);
        xor_nonce( checksum, c_N_0, 16);
	    aes128_encrypt_ffs(checksum, checksum, checksum, checksum, rkeys_ffs);
        xor_nonce( checksum, S, 16);
        xor_nonce( tag, checksum, 16);
    }



}

void PMAC( unsigned char* nonce, unsigned char* asociated_data, unsigned int asociated_data_size,
        unsigned char* key, unsigned char* tag){

    uint32_t size_ptext = (asociated_data_size/2) + 16;
    uint32_t size = 0;

    if (asociated_data_size%16 == 0 ){
        size = asociated_data_size/16;
    }else{
        size = asociated_data_size/16+1;
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
    
    unsigned char key_2AES[key_size] = {0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3};

    unsigned char N_0[16];
    unsigned char N_1[16];

    unsigned char N_0_t[16];
    unsigned char N_1_t[16];

    unsigned char c_N_0[16];
    unsigned char c_N_1[16];
    unsigned char checksum[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    unsigned int add_nonce_0[4] = {0,0,0,0};
    unsigned int add_nonce_1[4] = {1,1,1,1};

    unsigned int add_nonce_2[4] = {2,2,2,2};
    
    divide_plaintext(asociated_data, ptext0,  ptext1, asociated_data_size);
    divide_key(key, key0, key1);

    //key schedule
	uint32_t rkeys_ffs[88];
    uint32_t two_AES_keys_ffs[88];

	aes128_keyschedule_ffs(rkeys_ffs, key0, key1);
    aes128_2rounds_keyschedule_ffs(two_AES_keys_ffs, key_2AES, key_2AES);

	//generate the N from nonce using 10 aes rounds
    aes128_encrypt_ffs(N_0, N_1, nonce, nonce, rkeys_ffs);

    for (size_t i = 0; i < size/2; i++){

        add_nonce(add_nonce_0, (unsigned int *)N_0,(unsigned int *)N_0_t, 4);
        add_nonce(add_nonce_1, (unsigned int *)N_1,(unsigned int *)N_1_t, 4);

        two_Rounds_aes128_encrypt_ffs(c_N_0,  c_N_1, N_0_t,  N_1_t, two_AES_keys_ffs);

        xor_nonce( ptext0 + (i*16), c_N_0, 16);
        xor_nonce( ptext1 + (i*16), c_N_1, 16);
	    
        aes128_encrypt_ffs(ctext0+ (i*16), ctext1+ (i*16), ptext0+ ((i)*16), ptext1 + (i*16), rkeys_ffs);
        

        xor_nonce( checksum, ctext0 + (i*16), 16);
        // print_array(checksum,16);
        xor_nonce( checksum, ctext1 + (i*16), 16);
        // print_array(checksum,16);

        add_nonce(add_nonce_2, add_nonce_0,add_nonce_0, 4);
        add_nonce(add_nonce_2, add_nonce_1,add_nonce_1, 4);
        
    }
    
    if (1)//condicion de bloques completos
    {
        // print_array((unsigned char *)add_nonce_0,16);
        // print_array((unsigned char *)add_nonce_1,16);

        add_nonce(add_nonce_1, (unsigned int *)N_0,(unsigned int *)N_0_t, 4);
        two_Rounds_aes128_encrypt_ffs(c_N_0,  c_N_1, N_0_t,  N_0_t, two_AES_keys_ffs);

        xor_nonce( checksum, c_N_0, 16);

	    aes128_encrypt_ffs(checksum, checksum, checksum, checksum, rkeys_ffs);

        xor_nonce( tag, checksum, 16);



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


void union_ciphertext(unsigned char* ciphertext, unsigned char* ctext0,  unsigned char* ctext1,unsigned int plaintext_size){

    // bool condicion = 1;
    int condicion = 1;
    size_t j=0;
    size_t k=0;
    for (size_t i = 0; i < plaintext_size; i++){
        if (i%16==0 && i!=0)
            condicion=condicion^1;
        
        if (condicion)
            ciphertext[i] = ctext0[j];
        else
            ciphertext[i] = ctext1[k];
        
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


void print_array(uint8_t * plaintext, uint32_t size){
    if (size>32)
    {
        for (size_t i = 0; i < 16; i++){
            printf("%02x ", plaintext[i]);
        }
        printf("............");
        for (size_t i = size-16; i < size; i++){
            printf("%02x ", plaintext[i]);
        }
    }else{
        for (size_t i = 0; i < size; i++){
            printf("%02x ", plaintext[i]);
        }
    }
    
    
    
    printf("\n");
}
