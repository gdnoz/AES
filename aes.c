#include <stdio.h>
#include <string.h>
#include "aessbox.c"
#include "matrix.c"
#include "key.c"

#define ROUNDS 10
#define BLOCK_WIDTH 4
#define BLOCK_SIZE (BLOCK_WIDTH*BLOCK_WIDTH)

unsigned char keySchedule[ROUNDS+1][BLOCK_SIZE];
unsigned int roundConstants[ROUNDS+1];

void printBlock(unsigned char* block)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        if (block[i] == '\0')
        {
            break;
        }

        printf("%x ", block[i]);

        if (i % BLOCK_WIDTH == 3)
        {
            printf("\n");
        }
    }
}

void printMsg(unsigned char* block, char* delim)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        if (block[i] == '\0')
        {
            break;
        }

        printf("%c", block[i]);
    }

    printf("%s", delim);
}

unsigned char mul2(unsigned char byte)
{
    if (byte & 0x80) // Is the most significant bit set?
    {
        return (byte << 1) ^ 0x1b; // evil Rijndel field bit-level hacking
    }
    else // If MSB == 0, just shift
    {
        return byte << 1;
    }
}

unsigned char mul3(unsigned char byte)
{
    return byte ^ mul2(byte);
}

unsigned char mul9(unsigned char byte)
{
    return byte ^ mul2(mul2(mul2(byte)));
}

unsigned char mulB(unsigned char byte)
{
    return byte ^ mul2(byte ^ mul2(mul2(byte)));
}

unsigned char mulD(unsigned char byte)
{
    return byte ^ mul2(mul2(byte ^ mul2(byte)));
}

unsigned char mulE(unsigned char byte)
{
    return mul2(byte ^ mul2(byte ^ mul2(byte)));
}

unsigned char mul(unsigned char byte, unsigned char factor)
{
    unsigned char ret = byte;

    //printf("\t%x * %x = ", byte, factor);

    switch(factor)
    {
        case 0x2:
        {
            ret = mul2(byte);
            break;
        }
        case 0x3:
        {
            ret = mul3(byte);
            break;
        }
        case 0x9:
        {
            ret = mul9(byte);
            break;
        }
        case 0xb:
        {
            ret = mulB(byte);
            break;
        }
        case 0xd:
        {
            ret = mulD(byte);
            break;
        }
        case 0xe:
        {
            ret = mulE(byte);
            break;
        }
    }

    //printf("%x\n", ret);

    return ret;
}

unsigned char* addRoundKey(unsigned char* block, unsigned char* key)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        //printf("%x + %x = %x\n", block[i], key[i], block[i] ^ key[i]);
        block[i] = block[i] ^ key[i];
    }

    return block;
}

unsigned char* doShiftRows(unsigned char* block, int inv)
{
    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        unsigned char row[BLOCK_WIDTH];

        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            if (inv)
            {
                row[(i+j)%BLOCK_WIDTH] = block[i*BLOCK_WIDTH+j];
            }
            else
            {
                row[j] = block[i*BLOCK_WIDTH+((i+j)%BLOCK_WIDTH)];
            }
        }

        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            block[j+i*BLOCK_WIDTH] = row[j];
        }
    }

    return block;
}

unsigned char* shiftRows(unsigned char* block)
{
    return doShiftRows(block, 0);
}

unsigned char* shiftRowsI(unsigned char* block)
{
    return doShiftRows(block, 1);
}

unsigned char* doMixColumns(unsigned char* block, unsigned char mat[BLOCK_WIDTH][BLOCK_WIDTH])
{
    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        unsigned char col[BLOCK_WIDTH];

        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            unsigned char val = 0;

            for (int k = 0; k < BLOCK_WIDTH; k++)
            {
                // Multiply block[i][k] with M[j][k]
                val ^= mul(block[i+k*BLOCK_WIDTH], mat[j][k]);
            }

            // Assign val to rorresponding column value
            col[j] = val;
            //printf("%x -> %x\n", block[i+j*BLOCK_WIDTH], val);
        }
        //printf("\n");

        // Assign calculated column values to corresponding block values
        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            block[i+j*BLOCK_WIDTH] = col[j];
        }
    }

    return block;
}

unsigned char* mixColumns(unsigned char* block)
{
    return (unsigned char*)doMixColumns((unsigned char*)block, M);
}

unsigned char* mixColumnsI(unsigned char* block)
{
    return (unsigned char*)doMixColumns((unsigned char*)block, MI);
}

unsigned char* doSubBytes(unsigned char* block, unsigned char* sBox)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        block[i] = sBox[block[i]];
    }

    return block;
}

unsigned char* subBytes(unsigned char* block)
{
    return (unsigned char*)doSubBytes((unsigned char*)block, S);
}

unsigned char* subBytesI(unsigned char* block)
{
    return (unsigned char*)doSubBytes((unsigned char*)block, SI);
}

unsigned char* getRoundKey(int rd)
{
    // Get previous key
    if (rd == 0)
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            keySchedule[rd][i] = KEY[i];
        }
    }
    else
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            keySchedule[rd][i] = keySchedule[rd-1][i];
        }
    }

    // Rotate all rows by 1
    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        unsigned char row[BLOCK_WIDTH];

        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            row[j] = keySchedule[rd][i*BLOCK_WIDTH+((1+j)%BLOCK_WIDTH)];
        }

        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            keySchedule[rd][j+i*BLOCK_WIDTH] = row[j];
        }
    }

    // Apply S-box
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        keySchedule[rd][i] = S[keySchedule[rd][i]];
    }

    // Add round constant
    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        keySchedule[rd][i*BLOCK_WIDTH] = keySchedule[rd][i*BLOCK_WIDTH] ^ roundConstants[rd];
    }

    // XOR each line with previous line
    unsigned char lastRow[BLOCK_WIDTH];

    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        lastRow[i] = keySchedule[rd][(BLOCK_WIDTH-1)*BLOCK_WIDTH+i];
    }

    for (int i = 0; i < BLOCK_WIDTH-1; i++)
    {
        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            keySchedule[rd][((i+1)%BLOCK_WIDTH)*BLOCK_WIDTH+j] = keySchedule[rd][((i+1)%BLOCK_WIDTH)*BLOCK_WIDTH+j] ^ keySchedule[rd][i*BLOCK_WIDTH+j];
        }
    }

    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        keySchedule[rd][i] = keySchedule[rd][i] ^ lastRow[i];
    }

    return keySchedule[rd];
}

int getRoundConstant(int rd)
{
    if (rd == 0)
    {
        roundConstants[rd] = 1;
    }
    else
    {
        roundConstants[rd] = mul2(roundConstants[rd-1]);
    }
    
    return roundConstants[rd];
}

void generateKeySchedule()
{
    for (int i = 0; i < ROUNDS+1; i++)
    {
        getRoundConstant(i);
        getRoundKey(i);
    }
}

unsigned char* encryptBlock(unsigned char* msg)
{
    int round = 0;

    // 1. generateKeySchedule
    generateKeySchedule();
    // 2. addRoundKey
    addRoundKey(msg, keySchedule[round]);
    // 3. 9 rounds:
    for (round++; round < ROUNDS; round++)
    {
        // 3.1. subBytes
        subBytes(msg);
        // 3.2. shiftRows
        shiftRows(msg);
        // 3.3. mixColumns
        mixColumns(msg);
        // 3.4. addRoundKey
        addRoundKey(msg, keySchedule[round]);
    }
    // 4. Final round
    // 4.1. subBytes
    subBytes(msg);
    // 4.2. shiftRows
    shiftRows(msg);
    // 4.3. addRoundKey
    addRoundKey(msg, keySchedule[round]);

    return msg;
}

unsigned char* decryptBlock(unsigned char* msg)
{
    int round = ROUNDS;

    // 1. addRoundKey
    addRoundKey(msg, keySchedule[round]);
    // 2. shiftRowsI
    shiftRowsI(msg);
    // 3. subBytesI
    subBytesI(msg);
    // 4. 9 rounds
    for (round--; round > 0; round--)
    {
        // 4.1. addRoundKey
        addRoundKey(msg, keySchedule[round]);
        // 4.2. mixColumnsI
        mixColumnsI(msg);
        // 4.3. shiftRowsI
        shiftRowsI(msg);
        // 4.4. subBytesI
        subBytesI(msg);
    }
    // 5. addRoundKey
    addRoundKey(msg, keySchedule[round]);

    return msg;
}

unsigned char* pad(unsigned char* msg, int len)
{
    // TODO: Implement some viable padding strategy
    for (int i = len; i < BLOCK_SIZE; i++)
    {
        msg[i] = '\0';
    }

    return msg;
}

int main()
{
    const unsigned char* msg = (unsigned char*)"Hello World!";// Hello World! Hello World! Hello World! Hello World! Hello World! Hello World!";
    unsigned char p[strlen((char*)msg)];

    strcpy((char*)p, (char*)msg);
    pad(p, strlen((char*)p)); // TODO: When implementing block chaining, only do this for the last block
    printMsg(p, "\n");
    encryptBlock(p);
    printMsg(p, "\n");
    decryptBlock(p);
    printMsg(p, "\n");

    return 0;
}