#include <stdio.h> 
#include "aes.h"
#include "internal-aes.h"

void print_array(uint8_t * plaintext, uint8_t size);
void OCB(unsigned char* ctext0, unsigned char * ctext1, 
        const unsigned char* ptext0, const unsigned char* ptext1, 
        const unsigned char * key0, const unsigned char * key1);
int main(){

    unsigned char key0[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};
	unsigned char key1[16]={0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 ,0x08,0x09,0x0a,0x0b ,0x0c,0x0d,0x0e,0x0f};
	unsigned char ctext0[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char ctext1[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char ptext0[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};
	unsigned char ptext1[16]={0,0,0,0, 0,0,0,0 ,0,0,0,0 ,0,0,0,0};

    print_array(key0,16);

    print_array(ptext0,16);


    OCB(ctext0, ctext1, ptext0,  ptext1, key0,  key1);

    print_array(ctext0,16);
    print_array(ctext1,16);


    return 0;
}




void OCB(unsigned char* ctext0, unsigned char * ctext1, 
        const unsigned char* ptext0, const unsigned char* ptext1, 
        const unsigned char * key0, const unsigned char * key1){

	uint32_t rkeys_ffs[88];

	aes128_keyschedule_ffs(rkeys_ffs, key0, key1);

    seven_Rounds_aes128_encrypt_ffs(ctext0, ctext1, ptext0, ptext1, rkeys_ffs);
	// aes128_encrypt_ffs(ctext0, ctext1, ptext0, ptext1, rkeys_ffs);

}


void print_array(uint8_t * plaintext, uint8_t size){
    for (size_t i = 0; i < size; i++){
        printf("%02x ", plaintext[i]);
    }
    printf("\n");
}
