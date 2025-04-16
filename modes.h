#include"AES.h"
#include "openssl/rand.h"

// Function to add PKCS7 padding
int pkcs7_pad(unsigned char* buf, int len, int block_size) 
{
    int padding_len = block_size - (len % block_size);
    for (int i = len; i < len + padding_len; i++) 
    {
        buf[i] = padding_len;
    }
    return len + padding_len;
}
    
// Function to remove PKCS7 padding
int pkcs7_unpad(unsigned char* buf, int len) {
    int padding_len = buf[len - 1];
    if (padding_len < 1 || padding_len > 16) return len;  // Invalid padding
    return len - padding_len;
}

//ECB Encryption function    
void ecbe(word w[44])
{
int i;
    unsigned char buf[32];  // Larger buffer to accommodate padding
    int fd;
    int nb_read;
    int fd1;
    unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    KeyExpansion((word*)key, w);

    fd1 = open("out.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);
    fd = open("input.txt", O_RDONLY);

    nb_read = read(fd, buf, 16);

    while (nb_read > 0)
    {   
        if (nb_read < 16) {
            // Add PKCS7 padding to the last block
            nb_read = pkcs7_pad(buf, nb_read, 16);
        }
        Cipher(buf, w);  // Direct ECB encryption
        write(fd1, buf, 16);
        nb_read = read(fd, buf, 16);
    }
    
    close(fd);
    close(fd1);
    
}



//ECB Decryption function    
void ecbd(word w[44])
{
int i;
    unsigned char buf[32];  // Larger buffer for handling padding
    int fd;
    int nb_read;
    int fd1;
    unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    KeyExpansion((word*)key, w);

    fd1 = open("output.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);
    fd = open("out.txt", O_RDONLY);

    nb_read = read(fd, buf, 16);

    while (nb_read > 0)
    {   
        DeCipher(buf, w);  // Direct ECB decryption
        // Remove PKCS7 padding for the last block
        if (nb_read < 16) {
            nb_read = pkcs7_unpad(buf, nb_read);
        }
        write(fd1, buf, nb_read);

        nb_read = read(fd, buf, 16);
    }
    
    close(fd);
    close(fd1);
   
}



//CBC Encryption function    
void cbce(word w[44],unsigned char IV[16])
{
RAND_bytes(IV,16);
    int i;
    unsigned char buf[32];  // Larger buffer to accommodate padding
    int fd;
    int nb_read;
    int fd1;
    unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    KeyExpansion((word*)key, w);
    

    fd1 = open("out.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);
    fd = open("input.txt", O_RDONLY);
write(fd1,IV,16);
    nb_read = read(fd, buf, 16);

    while (nb_read > 0)
    {   
        if (nb_read < 16) {
            // Add PKCS7 padding to the last block
            nb_read = pkcs7_pad(buf, nb_read, 16);
        }
        for(i=0;i<16;i++)
        {
            IV[i]=buf[i] ^ IV[i];
        }
        Cipher(IV, w);
        write(fd1, IV, 16);
        nb_read = read(fd, buf, 16);
    }
    
    close(fd);
    close(fd1);
    
}



//CBC Decryption function    
void cbcd(word w[44],unsigned char IV[16])
{
int i, count=0;
    unsigned char buf[32], buf0[32];  // Larger buffer for handling padding
    int fd;
    int nb_read;
    int fd1;
    unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    KeyExpansion((word*)key, w);
    

    fd1 = open("output.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);
    fd = open("out.txt", O_RDONLY);
    int size=lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
	 count++;
	 read(fd, IV,16);
    nb_read = read(fd, buf, 16);
    
	 
    while (nb_read > 0)
    {   
        for(i=0;i<16;i++)
        {
            buf0[i]=buf[i];
        }
        DeCipher(buf, w);
        for(i=0;i<16;i++)
        {
            buf[i] = buf[i] ^ IV[i];
            IV[i] = buf0[i];
        }
         
      
        // Remove PKCS7 padding for the last block
        if (count= size /16) 
        {
            nb_read = pkcs7_unpad(buf, nb_read);
        }
        write(fd1, buf, nb_read);

        nb_read = read(fd, buf, 16);
        count++;
    }
    
    close(fd);
    close(fd1);
    
}



//CFB Encryption function    
void cfbe(word w[44],unsigned char IV[16])
{
int i;
unsigned char buf[16], buf1[16];
int fd;
int nb_read;
int fd1;
RAND_bytes(IV,16);
unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

KeyExpansion((word*)key, w);


fd1 = open("out.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);

fd = open("input.txt", O_RDONLY);
write(fd1,IV,16);
nb_read = read(fd, buf, 16);
while (nb_read > 0)
	{	
   
   Cipher(IV,w);
   for(i=0;i<16;i++)
     {
   	IV[i]=buf[i] ^ IV[i];
     }
   	write(fd1,IV,nb_read);
	 	nb_read = read(fd, buf, 16);
	}
	
	
	
close(fd);
close(fd1);


}


//CFB Decryption function    
void cfbd(word w[44],unsigned char IV[16])
{
int i;
unsigned char buf[16], buf0[16], buf1[16];
int fd;
int nb_read;
int fd1;
unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

KeyExpansion((word*)key, w);


fd1 = open("output.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);

fd = open("out.txt", O_RDONLY);
read(fd, IV,16);
nb_read = read(fd, buf, 16);
while (nb_read > 0)
	{	
   
   Cipher(IV,w);
   for(i=0;i<16;i++)
     {
   	buf0[i]=buf[i] ^ IV[i];
   	IV[i]=buf[i];
     }
     
   	write(fd1,buf0,nb_read);
	 	nb_read = read(fd, buf, 16);
	}
	
	
	
close(fd);
close(fd1);


}


//OFB Encryption function    
void ofbe(word w[44],unsigned char IV[16])
{
int i;
unsigned char buf[16], buf1[16];
int fd;
int nb_read;
int count;
int fd1;
RAND_bytes(IV,16);
unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

KeyExpansion((word*)key, w);


fd1 = open("out.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);

fd = open("input.txt", O_RDONLY);
write(fd1,IV,16);
nb_read = read(fd, buf, 16);
while (nb_read > 0)
	{	
   
   Cipher(IV,w);
   for(i=0;i<16;i++)
     {
   	buf[i]=buf[i] ^ IV[i];
     }
   	write(fd1,buf,nb_read);
	 	nb_read = read(fd, buf, 16);
	}
	
	
	
close(fd);
close(fd1);


}


//OFB Decryption function    
void ofbd(word w[44],unsigned char IV[16])
{
int i;
unsigned char buf[16], buf1[16];
int fd;
int nb_read;
int count;
int fd1;
unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

KeyExpansion((word*)key, w);

fd1 = open("output.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);


fd = open("out.txt", O_RDONLY);
read(fd, IV,16);
nb_read = read(fd, buf, 16);
while (nb_read > 0)
	{	
   
   Cipher(IV,w);
   for(i=0;i<16;i++)
     {
   	buf[i]=buf[i] ^ IV[i];
     }
   	write(fd1,buf,nb_read);
	 	nb_read = read(fd, buf, 16);
	}
	
	
	
close(fd);
close(fd1);


}


//Counter Mode Encryption function    
void ctre(word w[44],unsigned char ctr[16])
{
RAND_bytes(ctr,16);
int i;
unsigned char buf[16], buf1[16];
int fd;
int nb_read;
int fd1;
unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

KeyExpansion((word*)key, w);

fd1 = open("out.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);

fd = open("input.txt", O_RDONLY);
write(fd1,ctr,16);
nb_read = read(fd, buf, 16);

while (nb_read > 0)
	{	
  	for(i=0;i<16;i++)
   {
   ctr[i]++;
   if(ctr[i]=0)
   	break;
   }
   Cipher(ctr,w);
   for(i=0;i<16;i++)
     {
   	buf[i]=buf[i] ^ ctr[i];
     }
   	write(fd1,buf,nb_read);
	 	nb_read = read(fd, buf, 16);
	}
	
	
	
close(fd);
close(fd1);


}


//Counter Mode Decryption function    
void ctrd(word w[44],unsigned char ctr[16])
{

int i;
unsigned char buf[16], buf1[16];
int fd;
int nb_read;
int fd1;
unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

KeyExpansion((word*)key, w);

fd1 = open("output.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);

fd = open("out.txt", O_RDONLY);
read(fd, ctr,16);
nb_read = read(fd, buf, 16);

while (nb_read > 0)
	{	
  	for(i=0;i<16;i++)
   {
   ctr[i]++;
   if(ctr[i]=0)
   	break;
   }
   Cipher(ctr,w);
   for(i=0;i<16;i++)
     {
   	buf[i]=buf[i] ^ ctr[i];
     }
   	write(fd1,buf,nb_read);
	 	nb_read = read(fd, buf, 16);
	}
	
	
	
close(fd);
close(fd1);

}
