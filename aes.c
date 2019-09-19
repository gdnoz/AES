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
        printf("%.2x ", block[i]);

        if (i % BLOCK_WIDTH == 3)
        {
            printf("\n");
        }
    }
}

void printBlocks(unsigned char* msg, int len)
{
    int blockNum = 0;
    int numOfBlocks = len/BLOCK_SIZE;

    while (blockNum < numOfBlocks)
    {
        printBlock(msg + blockNum*BLOCK_SIZE);
        blockNum++;
        printf("\n");
    }

    printf("\n");
}

void printLine(unsigned char* block)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        printf("%.2x", block[i]);
    }
    printf("\n");
}

void printLineCol(unsigned char* block)
{
    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            printf("%.2x", block[j*BLOCK_WIDTH+i]);
        }
    }
    printf("\n");
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

    return ret;
}

unsigned char* addRoundKey(unsigned char* block, unsigned char* key)
{
    // for (int i = 0; i < BLOCK_SIZE; i++)
    // {
    //     printf("\t%x ^ %x = %x\n", block[i], key[i], block[i] ^ key[i]);
    //     block[i] = block[i] ^ key[i];
    // }
    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            // printf("\t%.2x ^ %.2x = %.2x\n", block[i*BLOCK_WIDTH+j], key[j*BLOCK_WIDTH+i], block[i*BLOCK_WIDTH+j] ^ key[j*BLOCK_WIDTH+i]);
            block[i*BLOCK_WIDTH+j] ^= key[j*BLOCK_WIDTH+i];
        }
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
        }

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
    // printf("\n\nROUND %i:\n", rd);
    // Get previous key
    if (rd == 0)
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            keySchedule[rd][i] = KEY[i];
        }
        // printBlock(keySchedule[rd]);
        return keySchedule[rd];
    }
    else
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            keySchedule[rd][i] = keySchedule[rd-1][i];
        }
    }

    // Store last row
    unsigned char lastRow[BLOCK_WIDTH];

    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        lastRow[i] = keySchedule[rd][(BLOCK_WIDTH-1)*BLOCK_WIDTH+i];
    }

    // Rotate all rows by 1
    unsigned char row[BLOCK_WIDTH];

    for (int j = 0; j < BLOCK_WIDTH; j++)
    {
        row[j] = keySchedule[rd][(BLOCK_WIDTH-1)*BLOCK_WIDTH+((1+j)%BLOCK_WIDTH)];
    }

    for (int j = 0; j < BLOCK_WIDTH; j++)
    {
        keySchedule[rd][j+(BLOCK_WIDTH-1)*BLOCK_WIDTH] = row[j];
    }

    // printf("Rotate by 1:\n");
    // printBlock(keySchedule[rd]);

    // Apply S-box
    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        keySchedule[rd][(BLOCK_WIDTH-1)*BLOCK_WIDTH+i] = S[keySchedule[rd][(BLOCK_WIDTH-1)*BLOCK_WIDTH+i]];
    }

    // printf("\nApply S-box:\n");
    // printBlock(keySchedule[rd]);

    // Add round constant
    keySchedule[rd][(BLOCK_WIDTH-1)*BLOCK_WIDTH] ^= roundConstants[rd];

    // printf("\nAdd round constant %i:\n", roundConstants[rd]);
    // printBlock(keySchedule[rd]);

    // XOR each line with previous line
    for (int i = 0; i < BLOCK_WIDTH-1; i++)
    {
        for (int j = 0; j < BLOCK_WIDTH; j++)
        {
            // printf("%i\n", ((BLOCK_WIDTH+(i-1))%BLOCK_WIDTH)*BLOCK_WIDTH+j);
            // printf("%x^%x\n", keySchedule[rd][i*BLOCK_WIDTH+j], keySchedule[rd][((BLOCK_WIDTH+(i-1))%BLOCK_WIDTH)*BLOCK_WIDTH+j]);
            keySchedule[rd][i*BLOCK_WIDTH+j] ^= keySchedule[rd][((BLOCK_WIDTH+(i-1))%BLOCK_WIDTH)*BLOCK_WIDTH+j];
        }
    }

    for (int i = 0; i < BLOCK_WIDTH; i++)
    {
        keySchedule[rd][(BLOCK_WIDTH-1)*BLOCK_WIDTH+i] = lastRow[i] ^ keySchedule[rd][(BLOCK_WIDTH-2)*BLOCK_WIDTH+i];
    }

    // printf("\nXOR with prev row:\n");
    // printBlock(keySchedule[rd]);

    return keySchedule[rd];
}

int getRoundConstant(int rd)
{
    if (rd == 0)
    {
        roundConstants[rd] = 0;
    }
    else if (rd == 1)
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

    // printf("\nROUND %i:\n", round);
    // 1. addRoundKey
    addRoundKey(msg, keySchedule[round]);
    // printf("Round %i (roundKey): ", round);
    // printLine(keySchedule[round]);
    // printf("Round %i (addRoundKey): ", round);
    // printLineCol(msg);
    // 2. 9 rounds:
    for (round++; round < ROUNDS; round++)
    {
        // printf("\nROUND %i:\n", round);
        // 2.1. subBytes
        subBytes(msg);
        // printf("Round %i (subBytes): ", round);
        // printLineCol(msg);
        // 2.2. shiftRows
        shiftRows(msg);
        // printf("Round %i (shiftRows): ", round);
        // printLineCol(msg);
        // 2.3. mixColumns
        mixColumns(msg);
        // printf("Round %i (mixColumns): ", round);
        // printLineCol(msg);
        // 2.4. addRoundKey
        addRoundKey(msg, keySchedule[round]);
        // printf("Round %i (roundKey): ", round);
        // printLine(keySchedule[round]);
        // printf("Round %i (addRoundKey): ", round);
        // printLineCol(msg);
    }

    // printf("\nROUND %i:\n", round);
    // 3. Final round
    // 3.1. subBytes
    subBytes(msg);
    // printf("Round %i (subBytes): ", round);
    // printLineCol(msg);
    // 3.2. shiftRows
    shiftRows(msg);
    // printf("Round %i (shiftRows): ", round);
    // printLineCol(msg);
    // 3.3. addRoundKey
    addRoundKey(msg, keySchedule[round]);
    // printf("Round %i (roundKey): ", round);
    // printLine(keySchedule[round]);
    // printf("Round %i (addRoundKey): ", round);
    // printLineCol(msg);

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

int pad(unsigned char* msg, const int len)
{
    int finalSize = len + (BLOCK_SIZE - (len % BLOCK_SIZE));
    int padding = 1;

    msg[len] = 0x80;

    for (int i = len+1; i < finalSize; i++)
    {
        padding++;
        msg[i] = 0x00;
    }

    return padding;
}

unsigned char* encryptECB(unsigned char* msg, int len)
{
    unsigned char* block;
    int blockNum = 0;
    int numOfBlocks = len/BLOCK_SIZE;

    while (blockNum < numOfBlocks)
    {
        block = msg + blockNum*BLOCK_SIZE;
        encryptBlock(block);
        blockNum++;
    }

    return msg;
}

unsigned char* decryptECB(unsigned char* msg, int len)
{
    unsigned char* block;
    int blockNum = 0;
    int numOfBlocks = len/BLOCK_SIZE;

    while (blockNum < numOfBlocks)
    {
        block = msg + blockNum*BLOCK_SIZE;
        decryptBlock(block);
        blockNum++;
    }

    return msg;
}

unsigned char* encryptCBC(unsigned char* msg, int len, unsigned char* iv)
{
    unsigned char* block;
    unsigned char* prev;
    int numOfBlocks = len/BLOCK_SIZE;
    int blockNum = 0;

    while (blockNum < numOfBlocks)
    {
        block = msg + blockNum*BLOCK_SIZE;

        if (blockNum == 0)
        {
            prev = iv;
        }
        else
        {
            prev = block-BLOCK_SIZE;
        }

        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            block[i] = block[i] ^ prev[i];
        }

        encryptBlock(block);
        blockNum++;
    }

    return msg;
}

unsigned char* decryptCBC(unsigned char* msg, int len, unsigned char* iv)
{
    unsigned char* block;
    unsigned char* prev;
    int numOfBlocks = len/BLOCK_SIZE;
    int blockNum = numOfBlocks-1;

    while (blockNum >= 0)
    {
        block = msg + blockNum*BLOCK_SIZE;

        if (blockNum == 0)
        {
            prev = iv;
        }
        else
        {
            prev = msg+(blockNum-1)*BLOCK_SIZE;
        }
        
        decryptBlock(block);

        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            block[i] = block[i] ^ prev[i];
        }

        blockNum--;
    }

    return msg;
}

int main()
{
    const char msg[] = "The quick brown fox boi jumps over the lazy doggo.";
    int inputLen = sizeof(msg)/sizeof(char);
    printf("inputLen = %i\n", inputLen);
    unsigned char p[inputLen + (BLOCK_SIZE - (inputLen % BLOCK_SIZE))];
    for (int i = 0; i < inputLen; i++)
    {
        p[i] = msg[i];
    }
    int paddedLen = inputLen + pad(p, inputLen);
    printf("paddedLen = %i\n", paddedLen);

    generateKeySchedule();

    printf("\nECB mode:\n");
    printBlocks(p, paddedLen);
    encryptECB(p, paddedLen);
    printBlocks(p, paddedLen);
    decryptECB(p, paddedLen);
    printBlocks(p, paddedLen);

    return 0;
}