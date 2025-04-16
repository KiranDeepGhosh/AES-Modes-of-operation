#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include "modes.h"
#include "openssl/rand.h"  
int main()
{
int x;
unsigned char IV[16];
RAND_bytes(IV,16);
unsigned char ctr[16];
RAND_bytes(ctr,16);
unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
word w[44];
KeyExpansion((word*)key, w);

printf("For ECB mode encryption and Decryption:1\nFor CBC mode encryption and Decryption:2\nFor OFB mode encryption and Decryption:3\nFor CFB mode encryption and Decryption:4\nFor Counter mode encryption and Decryption:5\n");
scanf("%d", &x);

if(x==1)
{
 ecbe(w); //ecb encryption
 ecbd(w); //ecb decryption
}

if(x==2)
{
 cbce(w,IV); //cbc encrption
 cbcd(w,IV); //cbc decrption
}

if(x==3)
{
 ofbe(w,IV); //ofb encrption
 ofbd(w,IV); //ofb decrption
}

if(x==4)
{	
 cfbe(w,IV); //cfb encrption
 cfbd(w,IV); //cfb decrption
}

if(x==5)
{
 ctre(w,ctr); //Counter encrption
 ctrd(w,ctr); //Counter decrption
 }			
return (0);

}
