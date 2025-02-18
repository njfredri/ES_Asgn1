/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

static uint16_t num_encryption_rounds = 10;

uint8_t s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

uint8_t inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

void sub_bytes(uint8_t s[4][4], uint8_t s_box[]){
    uint8_t temp[4][4];
    for (int i =0; i < 4; i++){
        for (int j=0; j < 4; j++){
            temp[i][j] = s_box[s[i][j]];
        }
    }
    for (int i =0; i < 4; i++){
        for (int j=0; j < 4; j++){
            s[i][j] = temp[i][j];
        }
    }
}
void inv_sub_bytes(uint8_t s[4][4], uint8_t inv_s_box[]){
    uint8_t temp[4][4];
    for (int i =0; i < 4; i++)
    {
        for (int j=0; j < 4; j++)
        {
            temp[i][j] = inv_s_box[s[i][j]];
        }
    }
    for (int i =0; i < 4; i++)
    {
        for (int j=0; j < 4; j++)
        {
            s[i][j] = temp[i][j];
        }
    }
}
// Now we need to add in the shift rows function. Recall that the first row doesn't shift,
// the second shifts just one to the left, the second two positions, and the third moves three. 
// We also need a function to inverse shift by doing the opposite.

// Despite what the colab code says, this is actually shifting columns

void shift_rows(uint8_t s[4][4]){ //This function takes in a 4x4 matrix, shifts all but the first row
    // s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    uint8_t temp = s[0][1];
    s[0][1] = s[1][1]; s[1][1] = s[2][1]; s[2][1] = s[3][1]; s[3][1] = temp;

    // s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    temp = s[0][2];
    uint8_t temp2 = s[1][2];
    s[0][2] = s[2][2]; s[1][2] = s[3][2]; s[2][2] = temp; s[3][2] = temp2;
    
    // s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
    temp = s[0][3];
    temp2 = s[1][3];
    uint8_t temp3 = s[2][3];
    s[0][3] = s[3][3]; s[1][3] = temp; s[2][3] = temp2; s[3][3] = temp3;
}


void inv_shift_rows(uint8_t s[4][4]){
    // s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    uint8_t temp = s[1][1];
    uint8_t temp2 = s[2][1];
    s[0][1] = s[3][1]; s[1][1] = s[0][1]; s[2][1] = temp; s[3][1] = temp2;

    // s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    temp = s[0][2];
    temp2 = s[1][2];
    s[0][2] = s[2][2]; s[1][2] = s[3][2]; s[2][2] = temp; s[3][2] = temp2;
    
    // s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
    temp = s[0][3];
    // temp2 = s[][3];
    // uint8_t temp3 = s[][3];
    s[0][3] = s[1][3]; s[1][3] = s[2][3]; s[2][3] = s[3][3]; s[3][3] = temp;
}


void print4x4(uint8_t s[4][4]){
    printf("\n");
    for (int i =0; i < 4; i++)
    {
        for (int j=0; j < 4; j++)
        {
            printf("%x ", s[i][j]);
        }
        printf("\n");
    }
}

uint8_t xtime(uint8_t a) {
    return (a & 0x80) ? (((a << 1) ^ 0x1B) & 0xFF) : (a << 1);
}

void mix_single_column(uint8_t a[4]){
    uint8_t t = a[0] ^ a[1] ^ a[2] ^ a[3];
    uint8_t u = a[0];
    a[0] ^= t ^ xtime(a[0] ^ a[1]);
    a[1] ^= t ^ xtime(a[1] ^ a[2]);
    a[2] ^= t ^ xtime(a[2] ^ a[3]);
    a[3] ^= t ^ xtime(a[3] ^ u);
}

void mix_columns(uint8_t s[4][4]){
    //Remove loop. S dimensions are hard coded anyways.
    mix_single_column(s[0]);
    mix_single_column(s[1]);
    mix_single_column(s[2]);
    mix_single_column(s[3]);

}

void inv_mix_columns(uint8_t s[4][4]){
    // # see Sec 4.1.3 in The Design of Rijndael
    for (int i=0; i<4; i++){
        uint8_t u = xtime(xtime(s[i][0] ^ s[i][2]));
        uint8_t v = xtime(xtime(s[i][1] ^ s[i][3]));
        s[i][0] ^= u;
        s[i][1] ^= v;
        s[i][2] ^= u;
        s[i][3] ^= v;
    }
    mix_columns(s);
}

void check_mix_columns(uint8_t s[4][4]){
    printf("\n----------Testing Check Mix--------------\n");
    print4x4(s);
    mix_columns(s);
    print4x4(s);
}

void check_inv_mix_columns(uint8_t s[4][4]){
    printf("\n----------Testing Check Inv Mix--------------\n");
    print4x4(s);
    inv_mix_columns(s);
    print4x4(s);
}

void add_round_key(uint8_t s[4][4], uint8_t k[4][4]){ //xor the state with a round key
  for(int i=0; i<4; i++)
  {
    for(int j=0; j<4; j++)
    {
        s[i][j] ^= k[i][j];
    }
  }
}

void check_add_round_key(uint8_t s[4][4]){
    uint8_t temp[4][4];
    for(int i=0; i<4; i++)
    {
        for(int j=0; j<4; j++)
        {
            temp[i][j] = s[i][j];
        }
    }
    uint8_t key[4][4] = {{1,3,5,7},{15,4,12,8},{15,2,2,2},{3,5,5,5}};
    printf("\n----------Testing Check Round Key--------------\n");
    print4x4(temp);
    add_round_key(temp,key);
    print4x4(temp);
}

// Round constants (Rcon array)
static const uint8_t r_con[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
};

void bytes2matrix(uint8_t key[16], uint8_t a[44][4]){
    for(int i=0; i<4; i++)
    {
        for(int j=0; j<4; j++)
        {
            a[i][j] = key[i*4 + j];
        }
  }
}

void getrow(int col, uint8_t a[44][4], uint8_t out[4]){
    for (int i=0; i<4; i++){
        out[i] = a[col][i];
    }
}

void printarray(int len, uint8_t *a){
    printf("\n");
    for (int i=0; i<len; i++)
    {
        printf("%x ", a[i]);
    }
    printf("   \n");

}

void printarraydec(int len, uint8_t *a){
    printf("\n");
    for (int i=0; i<len; i++)
    {
        printf("%d ", a[i]);
    }
    printf("   \n");

}

void circularshift(int len, uint8_t *a){
    uint8_t temp = a[0];
    for(int i=1; i<len; i++)
    {
        a[i-1] = a[i];
    }
    a[len-1] = temp;
}

void maptosbox(uint8_t word[4], uint8_t *sbox)
{
    for (int i=0; i<4; i++) {word[i] = sbox[word[i]];} //substitutes values in word using sbox
}

void xor_bytes(uint8_t *a, uint8_t *b) //assume 4 bytes
{
    // uint64_t a2 = ((uint64_t)a[0] << 24) | ((uint64_t)a[1] << 16) | ((uint64_t)a[2] << 8) | ((uint64_t)a[3]);
    // uint64_t b2 = ((uint64_t)b[0] << 24) | ((uint64_t)b[1] << 16) | ((uint64_t)b[2] << 8) | ((uint64_t)b[3]);
    

    // uint64_t c2 = a2^b2;

    // printf("Concatenated 64-bit a: 0x%016llX\n", a2);
    // printf("Concatenated 64-bit b: 0x%016llX\n", b2);
    // printf("Concatenated 64-bit c: 0x%016llX\n", c2);
    for (int i=0; i<4; i++)
    {
        // uint64_t temp = (c2 >> 8*i) & 0xFF;
        printf("\nai, bi, ci: %x %x %x", a[i], b[i], a[i]^b[i]);
        // a[i] = (uint8_t) temp;
        a[i] = a[i]^b[i];
    }
}

void expand_key(uint8_t *master_key, uint8_t keys[11][4][4]){
    // Expands and returns a list of key matrices for the given master_key.
    // Master key must be an array of 16 unsigned bytes

    // Initialize round keys with raw key material.
    // key_columns = bytes2matrix(master_key)
    uint8_t keycolumns[44][4];
    bytes2matrix(master_key, keycolumns);
    // print4x4(keycolumns);
    int iteration_size = 4; //length of masterkey (16 bytes) / 4

    int i = 1;
    int kclen = 4;
    uint8_t word[4];
    uint8_t previous_iteration_word[4];
    while (kclen < 44)
    {
        getrow(kclen-1, keycolumns, word);
        printf("-----------------------\n%d\nprevious word:", kclen);
        printarraydec(4, word);
        if (kclen % iteration_size == 0)
        {
            printf("kclen\%4 == 0\t now circular shifting");
            //circular shift
            circularshift(4, word);
            printarraydec(4, word);
            printf("\nnow mapping to sbox");
            //Map to S-Box
            maptosbox(word, s_box);
            printarraydec(4, word);
            printf("\nnow XOR with RCON");
            // XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i];
            printf("\nRCON[%d]: %d", i, r_con[i]);
            printarraydec(4, word);
            i += 1;
        }
        //removed as master key length is required to be 32 bytes for this 
        //master key is required to be 16 bytes
        // else if (kclen % iteration_size == 4) 
        // {
        //     printf("kclen\%4 == 4\t now circular shifting");

        // }
        printf("\nnow XOR with previous word");
        // # XOR with equivalent word from previous iteration.
        getrow(kclen-iteration_size, keycolumns, previous_iteration_word);
        printf("\nprevious word:");
        printarraydec(4, previous_iteration_word);
        xor_bytes(word, previous_iteration_word);
        printf("\nfinal word:");
        printarraydec(4, word);
        //append word to keycolumns
        for (int i=0; i<4; i++){keycolumns[kclen][i] = word[i];}
        kclen += 1;
    }

    //Set the values in the keys array
    for (int k=0; k<11; k++)
    {
        for(int i=0; i<4; i++)
        {
            for(int j=0; j<4; j++)
            {
                keys[k][i][j] = keycolumns[k*4 + i][j];
            }
        }
    }
}

void printkeys(uint8_t keys[11][4][4])
{
    
    for (int k=0; k<11; k++)
    {        
        printf("---------------------------------\n");
        printf("Key #%d\n", k);
        for(int i=0; i<4; i++)
        {
            for(int j=0; j<4; j++)
            {
                printf("%d ", keys[k][i][j]);
            }
            printf("\n");
        }
        printf("---------------------------------\n");
    }
}

int main(void)
{
    uint8_t test[4][4] = {{1,2,3,4},{5,6,7,8},{9,10,11,12},{13,14,15,0}};
    print4x4(test);
    // shift_rows(test);
    // print4x4(test);
    // inv_shift_rows(test);
    // print4x4(test);
    // sub_bytes(test, s_box);
    // print4x4(test);
    // inv_sub_bytes(test, inv_s_box);
    // print4x4(test);
    check_mix_columns(test);
    check_inv_mix_columns(test);
    check_add_round_key(test);
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t keys[11][4][4];
    expand_key(key, keys);
    printkeys(keys);
}
