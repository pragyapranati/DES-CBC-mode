#include <iostream>
#include <vector>
#include <fstream>
#include <bitset>
#include <iomanip>
#include <random>
#include <algorithm>
#include <sstream>
using namespace std;

int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7};
int FP[] = {40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25};
int E[] = {32, 1, 2, 3, 4, 5, 4, 5,
           6, 7, 8, 9, 8, 9, 10, 11,
           12, 13, 12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21, 20, 21,
           22, 23, 24, 25, 24, 25, 26, 27,
           28, 29, 28, 29, 30, 31, 32, 1};
int PC1[] = {57, 49, 41, 33, 25, 17, 9, 1,
             58, 50, 42, 34, 26, 18, 10, 2,
             59, 51, 43, 35, 27, 19, 11, 3,
             60, 52, 44, 36, 63, 55, 47, 39,
             31, 23, 15, 7, 62, 54, 46, 38,
             30, 22, 14, 6, 61, 53, 45, 37,
             29, 21, 13, 5, 28, 20, 12, 4};
int PC2[] = {14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
             23, 19, 12, 4, 26, 8,
             16, 7, 27, 20, 13, 2,
             41, 52, 31, 37, 47, 55,
             30, 40, 51, 45, 33, 48,
             44, 49, 39, 56, 34, 53,
             46, 42, 50, 36, 29, 32};
int S[8][4][16] = {
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},

    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 2, 8, 4, 7, 12, 11},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 7, 2, 12, 11, 1, 10, 14, 5},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 2, 12, 5}},

    {{7, 13, 14, 3, 0, 6, 9, 10, 2, 8, 5, 12, 4, 11, 15, 1},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},

    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 6, 9, 5, 0, 15, 14, 3, 8, 12},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},

    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 14, 1, 7, 6, 11, 0, 8, 13}},

    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 4, 9, 1, 12, 3, 7, 2, 8, 14, 15, 0, 5, 10}},

    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 5, 0, 15, 14, 2, 3, 10, 6, 8, 13},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 6, 3, 5, 11}}};
int P[] = {16, 7, 20, 21, 29, 12, 28, 17,
           1, 15, 23, 26, 5, 18, 31, 10,
           2, 8, 24, 14, 32, 27, 3, 9,
           19, 13, 30, 6, 22, 11, 4, 25};

vector<bool> xorOperation(const vector<bool> &a, const vector<bool> &b)
{
    vector<bool> result(a.size());
    for (size_t i = 0; i < a.size(); ++i)
    {
        result[i] = a[i] ^ b[i];
    }
    return result;
}
vector<bool> sBoxFunction(const vector<bool> &input)
{
    vector<bool> output(32);
    for (int i = 0; i < 8; ++i)
    {
        int row = (input[i * 6] << 1) | input[i * 6 + 5];
        int col = (input[i * 6 + 1] << 3) | (input[i * 6 + 2] << 2) | (input[i * 6 + 3] << 1) | input[i * 6 + 4];
        int sValue = S[i][row][col];
        for (int j = 0; j < 4; ++j)
        {
            output[i * 4 + j] = (sValue >> (3 - j)) & 1;
        }
    }
    return output;
}
vector<bool> permute(const vector<bool> &input, const int *table, int size)
{
    vector<bool> output(size);
    for (int i = 0; i < size; ++i)
    {
        output[i] = input[table[i] - 1];
    }
    return output;
}
vector<bool> desFunction(const vector<bool> &right, const vector<bool> &key)
{
    vector<bool> expanded = permute(right, E, 48);                  // Expand the r-half
    vector<bool> xorResult = xorOperation(expanded, key);           // XOR with the key
    vector<bool> sBoxOutput = sBoxFunction(xorResult);              // S-Box 
    return permute(sBoxOutput, P, 32);                              // P-Box 
}


vector<bool> desEncrypt(const vector<bool> &input, const vector<vector<bool>> &keys)
{
    vector<bool> permutedInput = permute(input, IP, 64);            // Initial permutation
    vector<bool> left(permutedInput.begin(), permutedInput.begin() + 32);
    vector<bool> right(permutedInput.begin() + 32, permutedInput.end());

    for (int i = 0; i < 16; ++i)
    {
        vector<bool> temp = right;                                  // Store the current r-half
        right = xorOperation(left, desFunction(right, keys[i]));    // DES function
        left = temp;                                                // Update left half
    }

    vector<bool> combined = right;                                  // r-half+left-half
    combined.insert(combined.end(), left.begin(), left.end());
    return permute(combined, FP, 64);                               // Final permutation
}

int shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
vector<vector<bool>> generateKeys(const vector<bool> &key)
{
    vector<vector<bool>> roundKeys(16, vector<bool>(48));
    vector<bool> permutedKey = permute(key, PC1, 56);
    vector<bool> C(permutedKey.begin(), permutedKey.begin() + 28);
    vector<bool> D(permutedKey.begin() + 28, permutedKey.end());
    for (int i = 0; i < 16; ++i)                                    // 16 r-keys
    {
        int shiftAmount = shifts[i];
        rotate(C.begin(), C.begin() + shiftAmount, C.end());
        rotate(D.begin(), D.begin() + shiftAmount, D.end());
        vector<bool> combined = C;
        combined.insert(combined.end(), D.begin(), D.end());
        roundKeys[i] = permute(combined, PC2, 48);
    }

    return roundKeys;
}

vector<unsigned char> readFile(const string &filename)
{
    ifstream file(filename, ios::binary);
    vector<unsigned char> data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return data;
}
void writeFile(const string &filename, const vector<unsigned char> &data)
{
    ofstream file(filename, ios::binary);
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
}
vector<unsigned char> padData(const vector<unsigned char> &data)
{
    size_t paddingSize = 8 - (data.size() % 8);
    vector<unsigned char> paddedData(data);
    paddedData.insert(paddedData.end(), paddingSize, static_cast<unsigned char>(paddingSize));
    return paddedData;
}
vector<bool> bytesToBits(const vector<unsigned char> &bytes)
{
    vector<bool> bits;
    for (unsigned char byte : bytes)
    {
        for (int i = 7; i >= 0; --i)
        {
            bits.push_back((byte >> i) & 1);
        }
    }
    return bits;
}
vector<unsigned char> bitsToBytes(const vector<bool> &bits)
{
    vector<unsigned char> bytes;
    for (size_t i = 0; i < bits.size(); i += 8)
    {
        unsigned char byte = 0;
        for (int j = 0; j < 8; ++j)
        {
            byte = (byte << 1) | bits[i + j];
        }
        bytes.push_back(byte);
    }
    return bytes;
}

vector<bool> desCBCEncrypt(const string &inputFile, const string &outputFile, const vector<bool> &key, const vector<bool> &iv)
{
    vector<unsigned char> plaintextData = readFile(inputFile);
    vector<unsigned char> paddedData = padData(plaintextData);
    vector<bool> bits = bytesToBits(paddedData);
    vector<vector<bool>> keys = generateKeys(key);
    vector<bool> ciphertextBits;
    vector<bool> previousCiphertext = iv;                           // Initial IV
    
    for (size_t i = 0; i < bits.size(); i += 64)
    {
        vector<bool> block(bits.begin() + i, bits.begin() + min(i + 64, bits.size()));
        block = xorOperation(block, previousCiphertext);             // XOR with previous ciphertext (or IV for the first block)
        vector<bool> encryptedBlock = desEncrypt(block, keys);       // Encrypt the block
        ciphertextBits.insert(ciphertextBits.end(), encryptedBlock.begin(), encryptedBlock.end());
        previousCiphertext = encryptedBlock;                         // Update the previous ciphertext to current block
    }

    vector<unsigned char> ciphertextBytes = bitsToBytes(ciphertextBits);
    writeFile(outputFile, ciphertextBytes);
}
vector<bool> desDecrypt(const vector<bool> &input, const vector<vector<bool>> &keys)
{
    return desEncrypt(input, vector<vector<bool>>(keys.rbegin(), keys.rend())); 
}
void desCBCDecrypt(const string &inputFile, const string &outputFile, const vector<bool> &key, const vector<bool> &iv)
{
    vector<unsigned char> ciphertextData = readFile(inputFile);
    vector<bool> bits = bytesToBits(ciphertextData);
    vector<vector<bool>> keys = generateKeys(key);
    vector<bool> plaintextBits;
    vector<bool> previousCiphertext = iv;                            // Initialize with IV

    for (size_t i = 0; i < bits.size(); i += 64)
    {
        vector<bool> block(bits.begin() + i, bits.begin() + min(i + 64, bits.size()));
        vector<bool> decryptedBlock = desDecrypt(block, keys);       // Decrypt the block
        vector<bool> originalBlock = xorOperation(decryptedBlock, previousCiphertext); // XOR with previous ciphertext or IV
        plaintextBits.insert(plaintextBits.end(), originalBlock.begin(), originalBlock.end());
        previousCiphertext = block;                                  // Update to current ciphertext block for the next iteration
    }

    // Remove padding after decryption
    vector<unsigned char> plaintextBytes = bitsToBytes(plaintextBits);
    size_t paddingSize = plaintextBytes.back();
    plaintextBytes.resize(plaintextBytes.size() - paddingSize);      // Remove padding

    writeFile(outputFile, plaintextBytes);
}


constexpr uint32_t h0 = 0x67452301;
constexpr uint32_t h1 = 0xEFCDAB89;
constexpr uint32_t h2 = 0x98BADCFE;
constexpr uint32_t h3 = 0x10325476;
constexpr uint32_t h4 = 0xC3D2E1F0;

constexpr uint32_t K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
uint32_t leftRotate(uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (32 - shift));
}

vector<unsigned char> padMessage(const vector<unsigned char>& data) {
    vector<unsigned char> paddedData(data);
    paddedData.push_back(0x80);
    while ((paddedData.size() * 8) % 512 != 448) {
        paddedData.push_back(0);
    }
    uint64_t originalBitLen = data.size() * 8;
    for (int i = 7; i >= 0; --i) {
        paddedData.push_back((originalBitLen >> (i * 8)) & 0xFF);
    }
    
    return paddedData;
}

string sha1(const vector<unsigned char>& data) {
    vector<unsigned char> paddedData = padMessage(data);
    uint32_t H[5] = { h0, h1, h2, h3, h4 };
    for (size_t chunkOffset = 0; chunkOffset < paddedData.size(); chunkOffset += 64) {
        uint32_t W[80] = {0};
        for (int i = 0; i < 16; ++i) {
            W[i] = (paddedData[chunkOffset + 4 * i] << 24) | 
                   (paddedData[chunkOffset + 4 * i + 1] << 16) |
                   (paddedData[chunkOffset + 4 * i + 2] << 8) |
                   (paddedData[chunkOffset + 4 * i + 3]);
        }
        for (int i = 16; i < 80; ++i) {
            W[i] = leftRotate(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
        }
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = K[0];
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = K[1];
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = K[2];
            } else {
                f = b ^ c ^ d;
                k = K[3];
            }
            
            uint32_t temp = leftRotate(a, 5) + f + e + k + W[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
    }
    stringstream hashStr;
    for (int i = 0; i < 5; ++i) {
        hashStr << hex << setw(8) << setfill('0') << H[i];
    }
    
    return hashStr.str();
}
int main()
{
    string inputFile = "input.txt";              // Input file with plaintext
    string outputFile = "ciphertext.bin";        // Output file for ciphertext
    string decryptedFile = "decrypted.txt";      // Output file for decrypted plaintext
    unsigned long long key = 0x133457799BBCDFF1; // Example key (64 bits)
    vector<bool> iv(64);                         // Example IV (to be generated randomly)

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, 1);
    for (int i = 0; i < 64; ++i)
    {
        iv[i] = dist(gen);
    }

    vector<bool> keyBits(64);
    for (int i = 0; i < 64; ++i)
    {
        keyBits[i] = (key >> (63 - i)) & 1;
    }

    desCBCEncrypt(inputFile, outputFile, keyBits, iv);
    desCBCDecrypt(outputFile, decryptedFile, keyBits, iv);

    ifstream originalFile(inputFile, ios::binary);
    vector<unsigned char> originalMessage((istreambuf_iterator<char>(originalFile)), {});

    ifstream decryptedFileStream(decryptedFile, ios::binary);
    vector<unsigned char> decryptedMessage((istreambuf_iterator<char>(decryptedFileStream)), {});

    string originalHash = sha1(originalMessage);
    string decryptedHash = sha1(decryptedMessage);

    if (originalHash == decryptedHash)
    {
        cout << "Success: SHA-1 hashes match!" << endl;
    }
    else
    {
        cout << "Error: SHA-1 hashes do not match!" << endl;
    }

    return 0;
}
