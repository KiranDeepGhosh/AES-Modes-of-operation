																																//S-box

unsigned char SBox[256] = {
//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F
																																//inverse S-box
unsigned char rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

																																	//definig structure (word)
typedef struct {

unsigned char bytes[4];

}word;

																																	//creat word function outputs keyword
word* create_word(unsigned char *key ){
int i;

word* keyword=(word*)malloc(4*sizeof(word)); 

for(i=0;i<4;i++)
  {
	keyword[i].bytes[0]=key[4*i+0];
	keyword[i].bytes[1]=key[4*i+1];
	keyword[i].bytes[2]=key[4*i+2];
	keyword[i].bytes[3]=key[4*i+3];
   }
return keyword;
}

																																	//Subword function
word SubWord(word *w) 
{
    word y;
    y.bytes[0] = SBox[w->bytes[0]];
    y.bytes[1] = SBox[w->bytes[1]];
    y.bytes[2] = SBox[w->bytes[2]];
    y.bytes[3] = SBox[w->bytes[3]];
    return y;
}
																																	//rotword Function
word RotWord(word *w) 	
{
    word y;
  
    y.bytes[0] = w->bytes[1];
    y.bytes[1] = w->bytes[2];
    y.bytes[2] = w->bytes[3];
    y.bytes[3] = w->bytes[0];
    return y;
}

																																	//Rcon
unsigned char Rcon[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

word addrcon(word *w, int i)	
{

	word z;
	int j;

	z.bytes[0]= w->bytes[0]^Rcon[i];

	for (j=1;j<4;j++)
		z.bytes[j]= w->bytes[j];

	return z;
}


																																	//keyExpansion fuction using rotword, subword and addroundkey
void KeyExpansion(word* keyword, word w[44]) {
    word temp;
    int j, i = 0;

   // Copy the initial key
    while (i < 4) {
        w[i] = keyword[i];
        i++;
    }

    // Expand the key
    while (i < 44) {
        temp = w[i - 1];
        if (i % 4 == 0) {
        
              
              temp = RotWord(&temp);
              temp = SubWord(&temp);
              temp = addrcon(&temp,i /4 );
        }
        
        for(j=0;j<4;j++){ 
        
        w[i].bytes[j] = w[i-4].bytes[j] ^ temp.bytes[j];
        }
        i++;
    }
}


																																	//define multiplication by x
unsigned char x_mul(unsigned char a) 
{
    // Define the multi
    unsigned char bitPattern = 0x1b;
    unsigned char b = a << 1;
    unsigned char c = a >> 7;
    return b ^ (c * bitPattern);
}

																																	//mixcoloumn function
void mixcoloumn(unsigned char state[4][4])
{
int i,j;
unsigned char s[4][4];
for(i=0;i<4;i++)
	{ 
	
		s[0][i] = (x_mul(state[0][i]))^(x_mul((state[1][i]))^(state[1][i]))^state[2][i]^state[3][i];
		s[1][i] = (state[0][i])^(x_mul(state[1][i]))^(x_mul((state[2][i]))^(state[2][i]))^state[3][i];
		s[2][i] = (state[0][i])^(state[1][i])^(x_mul(state[2][i]))^(x_mul(state[3][i])^(state[3][i]));
		s[3][i] = (x_mul(state[0][i])^(state[0][i]))^(state[1][i])^state[2][i]^x_mul((state[3][i]));
	
	}
 for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		
		state[i][j]=s[i][j];
		
	
	
	}

}

																																	//addroundkey function
void addrkey(unsigned char state[4][4], int roundnum, word wkey[44])  
{
    int i,j;
    for(j=0;j<4;j++)
   {
    for(i=0;i<4;i++)
	 	{ 
	    state[i][j]=state[i][j]^wkey[4*roundnum+j].bytes[i];
	 	}
	}
}

																																	//shiftrow function
void shiftrow(unsigned char state[4][4])

	{
		unsigned char temp;

    // Shift Row 1 
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Shift Row 2 
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift Row 3
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
	}


																																	//subbyte function
void subbyte(unsigned char state[4][4])

{
int i,j;
for(i=0;i<4;i++)
	{ 
		for(j=0;j<4;j++)
		state[i][j]=SBox[state[i][j]];

	}
}
																																	//inverse subbyte function
void invsubbyte(unsigned char state[4][4]){
int i,j;
for(i=0;i<4;i++){ 
for(j=0;j<4;j++)
state[i][j]=rsbox[state[i][j]];

}

}

																																	//inverse subbyte function
void invshiftrow(unsigned char state[4][4])

	{
		unsigned char temp;

    // Shift Row 1 
    temp = state[1][0];
    state[1][0] = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = temp;

    // Shift Row 2 
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3]=temp;

    // Shift Row 3
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
	}




																																//defining multiplications for hex value 0e using x_mul
unsigned char e_mul(unsigned char b) 

{
    // Define the multi
    
  return  x_mul(x_mul(x_mul(b)) ^ x_mul(b)^b); 

}
																																//defining multiplications for hex value 0b using x_mul
unsigned char b_mul(unsigned char b) 

{
    // Define the multi
    
  return  x_mul(x_mul(x_mul(b))) ^ x_mul(b)^b; 

}
																																//defining multiplications for hex value 0d using x_mul
unsigned char d_mul(unsigned char b) 

{
    // Define the multi
    
  return  x_mul(x_mul(x_mul(b))) ^ x_mul(x_mul(b))^b; 

}
																																//defining multiplications for hex value 09 using x_mul
unsigned char nine_mul(unsigned char b) 

{
    // Define the multi
    
  return  x_mul(x_mul(x_mul(b)))^b; 

}
																																//inverse mix colomn function
void invmixcoloumn(unsigned char state[4][4])
{
int i,j;
unsigned char s[4][4];
for (i = 0; i < 4; i++) 
	{

      s[0][i] = e_mul(state[0][i]) ^ b_mul(state[1][i]) ^ d_mul(state[2][i]) ^ nine_mul(state[3][i]);
      
        s[1][i] = nine_mul(state[0][i]) ^ e_mul(state[1][i]) ^ b_mul(state[2][i]) ^ d_mul(state[3][i]);
        
        s[2][i] = d_mul(state[0][i]) ^ nine_mul(state[1][i]) ^ e_mul(state[2][i]) ^ b_mul(state[3][i]);
        
        s[3][i] = b_mul(state[0][i]) ^ d_mul(state[1][i]) ^ nine_mul(state[2][i]) ^ e_mul(state[3][i]); 
    }
 for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		
		state[i][j]=s[i][j];
		
	}

}

																																	//defining encryption function
void Cipher(unsigned char input[16], word w[44])
{
unsigned char  state[4][4];
int roundnum;
int i,j;
for (int j = 0; j < 4; j++)
    {
        for (int i = 0; i < 4; i++)
        {
            state[i][j] = input[4 * j + i];
        }
    }
addrkey ( state,0, w );

for(roundnum=1;roundnum<10;roundnum++)

	{       
subbyte(state); 
shiftrow(state);
mixcoloumn(state);
addrkey(state,roundnum, w);
	}

subbyte(state);
shiftrow(state);
addrkey(state,10, w);

for (int j = 0; j < 4; j++)
    {
        for (int i = 0; i < 4; i++)
        {
            input[4 * j + i]=state[i][j] ;
        }
    }
}


																																	//defining dycripction function
void DeCipher(unsigned char input[16], word w[44])
{
unsigned char state[4][4];
int roundnum;
int i,j;
for (int j = 0; j < 4; j++)
    {
        for (int i = 0; i < 4; i++)
        {
            state[i][j] = input[4 * j + i];
        }
    }
addrkey ( state,10, w );
for(roundnum=9;roundnum>0;roundnum--)

	{       
invshiftrow(state); 
invsubbyte(state);
addrkey(state,roundnum, w);
invmixcoloumn(state);
	}

invshiftrow(state);
invsubbyte(state);
addrkey(state,0, w);
for (int j = 0; j < 4; j++)
    {
        for (int i = 0; i < 4; i++)
        {
            input[4 * j + i]=state[i][j] ;
        }
    }
}



