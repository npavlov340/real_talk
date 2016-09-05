/*
Nikolay Pavlov
CSC 650
Project 1

DES code has functions taken and edited from http://www.pracspedia.com/INS/DES-java.html,
some functions like S, fFN, are left exactly as is. 

ECB and CBC error messages check the String that the bits are initially stored,
if the bit size is not exactly 64 and error message will be thrown. Messing with 
the test cases it seems to work fine, but I have no idea if skewed results may
happen with new test cases if size is not 64 bits; Since again, I am checking
the String size and not the array size, because the array automatically is padded
with 0's in Java.

Also, I made the plaintext array and 2d M block plain text array expand by 64 bits
for every one bit the plain text is over 64 bits. So if plaintext was 129 bits, the array
would expand to 192 bits and the 2d array to 3 blocks. So far this has produced no errors and the
test cases remained the same result. However this was a last minute fix and I am not sure
if this may produce an error with new test cases.
 */
package crypto;

import java.*;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.Random;
import java.util.ArrayList;
import static java.lang.Math.*;
public class Crypto {

    private static int[] C = new int[28];
    private static int[] D = new int[28];
    private static int CnDn[] = new int[56];
    //private static int[] finalecb = new int[128];
    //private static int[] finalcbc = new int[128];

//Permutation Tables
    private static final byte[] IP = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final byte[] PC1 = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };

    private static final byte[] PC2 = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    private static final byte[] FP = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

//This table is for Ln = Rn-1, Rn = Ln-1 + f(Rn-1,Kn)
    private static final byte[] E = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

//Table used for S-boxes
    private static final byte[] P = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };

//S-Boxes
    private static final byte[][] S = {{
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    }, {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    }, {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    }, {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    }, {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    }, {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    }, {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    }, {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }};

//Permutation Function
    private static int[] permute(int[] input) {
        int[] permutetext = new int[input.length];
        for (int i = 0; i < input.length; i++) {
            permutetext[i] = input[IP[i] - 1];
        }
        return permutetext;
    }

//Rotation for Left Shit durng 16 Round Robin
    private static final int[] rotations = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

//DES checks lengths, then calls subkey which returns cyphertext
    static int[] DES(int[] plaintext, int[] key) {
        if (key.length != 64) {
            System.out.println("Error, Key not 64 bits");
            System.exit(0);
        }

        if (plaintext.length != 64) {
            System.out.println("Error, Plaintext not 64 bits");
            System.exit(0);
        }
        int[] DesCypher = new int[64];
        DesCypher = subkey(plaintext, key);
        return DesCypher;
    }
//CBC code, converts to bits and returns decimal array

    private static int[] CBC(String plaintext, String key, String IV) {

        byte[] bytes = plaintext.getBytes();
        byte[] bytes2 = key.getBytes();
        byte[] bytes3 = IV.getBytes();
        StringBuilder binary = new StringBuilder();
        StringBuilder binary2 = new StringBuilder();
        StringBuilder binary3 = new StringBuilder();

        //Convert Strings to binary
        for (byte b : bytes) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }

        }
        for (byte b : bytes2) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary2.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }

        }
        for (byte b : bytes3) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary3.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }

        }
        //Convert binary to String
        String test = binary.toString();
        String test2 = binary2.toString();
        String test3 = binary3.toString();

        if (test2.length() != 64) {
            System.out.println();
            System.out.println("Error, Key not 64 bits");
            System.exit(0);
        }

        if (test3.length() != 64) {
            System.out.println();
            System.out.println("Error, IV not 64 bits");
            System.exit(0);
        }

        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println("'" + plaintext + "' to binary: " + binary);
        System.out.println();
        System.out.println("Key: '" + key + "' to binary: " + binary2);
        System.out.println();
        System.out.println("IV: '" + IV + "' to binary: " + binary3);
        System.out.println();
        System.out.println("CBCTestPlainText:   " + test);
        System.out.println();
        System.out.print("Test length is: " + test.length());
        System.out.println();
        System.out.print("CBC Char is: ");
 double e = Math.ceil((double)test.length()/64);
        int ez = (int) e;
        int[] plain = new int[ez*64];
        int[] ecbkey = new int[64];
        int[] IVkey = new int[64];
        double r = Math.ceil((double)test.length()/64);
        int row = (int) r;
        //System.out.println();
        //System.out.print("ROW IS: " +row);
        int[] ecbkeyblock = new int[64];
        int[][] plainblock = new int[row][64];

        int j = 0, j2 = 0, j3 = 0;
        //Convert String Binary to Int Array
        System.out.println();
        System.out.print("CBC IV Char is: ");
        for (int i = 0; i < test3.length(); i++) {
            char d = test3.charAt(i);
            if (!Character.isWhitespace(d)) {
                IVkey[j3] = java.lang.Character.getNumericValue(d);
                j3++;
                System.out.print(java.lang.Character.getNumericValue(d));
            }
        }

        System.out.println();
        System.out.print("CBC Char is: ");
        for (int i = 0; i < test2.length(); i++) {
            char d = test2.charAt(i);
            if (!Character.isWhitespace(d)) {
                ecbkey[j2] = java.lang.Character.getNumericValue(d);
                j2++;
                System.out.print(java.lang.Character.getNumericValue(d));
            }
        }
        System.out.println();
        System.out.print("CBC Char Length: " + ecbkey.length);
        System.out.println();

        for (int i = 0; i < ecbkeyblock.length; i++) {
            ecbkeyblock[i] = ecbkey[i];
        }
        System.out.println();

        System.out.print("CBC BLOCK: ");
        for (int h = 0; h < ecbkeyblock.length; h++) {
            System.out.print(ecbkeyblock[h]);
        }

        System.out.println();

        for (int i = 0; i < test.length(); i++) {
            char c = test.charAt(i);
            if (!Character.isWhitespace(c)) {
                plain[j] = java.lang.Character.getNumericValue(c);
                j++;
                System.out.print(java.lang.Character.getNumericValue(c));
            }
        }

        int p = 0;
        for (int i = 0; i < plainblock.length; i++) {
            for (int k = 0; k < plainblock[i].length; k++) {
                plainblock[i][k] = plain[p];
                p++;
            }
        }

     //   for (int i = 0; i < plainblock.length; i++) {
      //      plainblock[1][i] = plain[i + 64];
      //  }

        System.out.println();
        System.out.print("ECB Int is:  ");

        for (int h = 0; h < plain.length; h++) {
            System.out.print(plain[h]);
        }

        System.out.println();
        System.out.print("ECB Block is:  ");

        for (int h = 0; h < plainblock.length; h++) {
            System.out.println();
            for (int y = 0; y < plainblock[h].length; y++) {
                System.out.print(plainblock[h][y]);
            }
        }
        //Run Encryption
        int[] finalcbc = new int[ez*64];
        finalcbc = CBCcypher(plainblock, ecbkeyblock, IVkey);

        System.out.println();

        System.out.print("Final CBC Output is:  ");
        for (int h = 0; h < finalcbc.length; h++) {
            System.out.print(finalcbc[h]);
        }
        ArrayList<Integer> ascii = new ArrayList<Integer>();
        ascii = ECBASCII(finalcbc);

        System.out.println();
        System.out.print("CbcCypherText:  ");
        for (Integer integer : ascii) {
            System.out.print(integer + "  ");
        }
        int[] finalcbccypher = new int[ascii.size()];
        int o = 0;
        for (Integer integer : ascii) {
            finalcbccypher[o] = integer;
            o++;
        }

        return finalcbccypher;
    }

    //Run encryption on CBC
    private static int[] CBCcypher(int[][] plainblock, int[] cbckeyblock, int[] IV) {

        int[] plain128 = new int[plainblock.length * plainblock[0].length];
        int[] finaloutput = new int[64];
        int[] finaloutput2 = new int[plainblock.length * 64];
        int[] temp = new int[64];
        int w = 0;
        //Split 2D array into 2 64 bits and run CBC encryption
        System.out.println();
        System.out.println("plain128 length is: " + plain128.length);
        for (int i = 0; i < plainblock.length; i++) {
            int[] row = plainblock[i];
            System.out.println();
            System.out.println("I is: " + i);
            System.out.print("Array Output is:  ");
            for (int j = 0; j < row.length; j++) {
                int number = plainblock[i][j];
                System.out.print(plainblock[i][j]);
                plain128[i * row.length + j] = number;
            }
            int[] plain64 = new int[64];
            for (int b = 0; b < plain64.length; b++) {
                plain64[b] = plain128[b + w];
            }
            temp = xor(plain64, IV);
            finaloutput = subkey(temp, cbckeyblock);
            for (int b = 0; b < finaloutput.length; b++) {
                finaloutput2[b + w] = finaloutput[b];
            }

            IV = finaloutput;
            w += 64;

        }

        return finaloutput2;
    }

    //ECB code, converts to bits and returns decimal array
    private static int[] ECB(String plaintext, String key) {

        byte[] bytes = plaintext.getBytes();
        byte[] bytes2 = key.getBytes();
        StringBuilder binary = new StringBuilder();
        StringBuilder binary2 = new StringBuilder();

        //Same as CBC, convert to bits, then String, then int array
        for (byte b : bytes) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }

        }
        for (byte b : bytes2) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary2.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }

        }

        String test = binary.toString();
        String test2 = binary2.toString();

        if (test2.length() != 64) {
            System.out.println();
            System.out.println("Error, Key not 64 bits");
            System.exit(0);
        }

        System.out.println();
        System.out.println("'" + plaintext + "' to binary: " + binary);
        System.out.println();
        System.out.println("'" + key + "' to binary: " + binary2);
        System.out.println();
        System.out.println("TestPlainText:   " + test);
        System.out.println();
        System.out.print("Test length is: " + test.length());
        System.out.println();
        double e = Math.ceil((double)test.length()/64);
        int ez = (int) e;
        int[] plain = new int[ez*64];

        int[] ecbkey = new int[64];
        double r = Math.ceil((double)test.length()/64);
        int row = (int) r;
        int[] ecbkeyblock = new int[64];
        int[][] plainblock = new int[row][64];

        int j = 0, j2 = 0;

        System.out.println();
        System.out.print("Char is: ");
        for (int i = 0; i < test2.length(); i++) {
            char d = test2.charAt(i);
            if (!Character.isWhitespace(d)) {
                ecbkey[j2] = java.lang.Character.getNumericValue(d);
                j2++;
                System.out.print(java.lang.Character.getNumericValue(d));
            }
        }
        System.out.println();
        System.out.print("Char Length: " + ecbkey.length);
        System.out.println();

        for (int i = 0; i < ecbkeyblock.length; i++) {
            ecbkeyblock[i] = ecbkey[i];
        }
        System.out.print("Plain Length: ");
        System.out.print(plain.length);
        System.out.println();

        System.out.print("ECB BLOCK: ");
        for (int h = 0; h < ecbkeyblock.length; h++) {
            System.out.print(ecbkeyblock[h]);
        }

        System.out.println();

        for (int i = 0; i < test.length(); i++) {
            char c = test.charAt(i);
            if (!Character.isWhitespace(c)) {
                plain[j] = java.lang.Character.getNumericValue(c);
                j++;
                System.out.print(java.lang.Character.getNumericValue(c));
            }
        }

        if (ecbkeyblock.length != 64) {
            System.out.println("Error, Key not 64 bits");
            System.exit(0);
        }

        System.out.println();
        int p = 0;
        for (int i = 0; i < plainblock.length; i++) {
            for (int k = 0; k < plainblock[i].length; k++) {
                plainblock[i][k] = plain[p];
                p++;
            }
        }

        for (int i = 0; i < plainblock.length; i++) {
            plainblock[1][i] = plain[i + 64];
        }

        System.out.println();
        System.out.print("Int is:  ");

        for (int h = 0; h < plain.length; h++) {
            System.out.print(plain[h]);
        }

        System.out.println();
        System.out.print("Block is:  ");

        for (int h = 0; h < plainblock.length; h++) {
            System.out.println();
            for (int y = 0; y < plainblock[h].length; y++) {
                System.out.print(plainblock[h][y]);
            }
        }
        //run ecb encryption
        int[] finalecb = new int[ez*64];        
        finalecb = ECBcypher(plainblock, ecbkeyblock);

        System.out.println();

        System.out.print("Final Output is:  ");
        for (int h = 0; h < finalecb.length; h++) {
            System.out.print(finalecb[h]);
        }
        ArrayList<Integer> ascii = new ArrayList<Integer>();
        ascii = ECBASCII(finalecb);

        System.out.println();
        System.out.print("EcbCypherText:  ");
        for (Integer integer : ascii) {
            System.out.print(integer + "  ");
        }
        int[] finalecbcypher = new int[ascii.size()];
        int o = 0;
        for (Integer integer : ascii) {
            finalecbcypher[o] = integer;
            o++;
        }

        return finalecbcypher;
    }

    //Get Decimal Values based of BitCode and return as ArrayList
    private static ArrayList<Integer> ECBASCII(int[] ecb) {
        int bits[] = new int[ecb.length];
        String bitstring = "";

        System.out.println();
        System.out.print("Bits:  ");
        for (int i = 0; i < bits.length; i++) {
            bits[i] = ecb[i];
            System.out.print(bits[i]);
            bitstring += bits[i];
        }
        System.out.println();
        System.out.print("Bitstring:  ");
        System.out.print(bitstring);
        System.out.println();

        ArrayList<Integer> intList = new ArrayList<Integer>();

        for (int i = 0; i < bitstring.length(); i += 8) {
            intList.add(Integer.parseInt(bitstring.substring(i, i + 8), 2));
            System.out.print(bitstring.substring(i, i + 8) + " ");
        }

        return intList;
    }

    //Run encryption on ECB
    private static int[] ECBcypher(int[][] plain, int[] key) {
        int[] plain128 = new int[plain.length * plain[0].length];
        int[] finaloutput = new int[64];
        int[] finaloutput2 = new int[plain.length * 64];
        int w = 0;
        //Same as CBC, split 2d array into 2 64 bits and run encryption
        System.out.println();
        System.out.println("plain128 length is: " + plain128.length);
        for (int i = 0; i < plain.length; i++) {
            int[] row = plain[i];
            System.out.println();
            System.out.println("I is: " + i);
            System.out.print("Array Output is:  ");
            for (int j = 0; j < row.length; j++) {
                int number = plain[i][j];
                System.out.print(plain[i][j]);
                plain128[i * row.length + j] = number;
            }
            int[] plain64 = new int[64];
            for (int b = 0; b < plain64.length; b++) {
                plain64[b] = plain128[b + w];
            }
            finaloutput = subkey(plain64, key);
            for (int b = 0; b < finaloutput.length; b++) {
                finaloutput2[b + w] = finaloutput[b];
            }
            w += 64;

        }

        return finaloutput2;
    }

    //Round Robin
    private static int[] roundRobin(int round, int[] key) {
        int Cn[] = new int[28];
        int Dn[] = new int[28];
        int tempkey[] = new int[48];
        int rotationTimes = rotations[round];
        Cn = shift(C, rotationTimes);
        Dn = shift(D, rotationTimes);
        for (int j = 0; j < 28; j++) {
            CnDn[j] = Cn[j];
        }
        for (int j = 0; j < 28; j++) {
            CnDn[j + 28] = Dn[j];
        }
        for (int i = 0; i < tempkey.length; i++) {
            tempkey[i] = CnDn[PC2[i] - 1];
        }
        C = Cn;
        D = Dn;
        return tempkey;
    }

    //DES Logic Code
    static int[] subkey(int[] input, int[] key) {
        int[] newkey = new int[56];
        int[] cyphertext = new int[64];
        int left[] = new int[32];
        int right[] = new int[32];
        int newright[] = new int[0];
        newkey = key;
        System.out.println();
        System.out.print("Plaintext:                 ");
        for (int k = 0; k < input.length; k++) {
            System.out.print(input[k] + ", ");
        }

        //Permute Plaintext
        input = permute(input);

        System.out.println();
        System.out.print("Plaintext Permuted:        ");
        for (int k = 0; k < input.length; k++) {
            System.out.print(input[k] + ", ");
        }

        System.out.println();
        System.out.print("Original KEY:  ");
        for (int i = 0; i < newkey.length; i++) {
            System.out.print(newkey[i] + ", ");
        }

        //Get 24 permuted bit key for C
        for (int j = 0; j < 28; j++) {
            C[j] = newkey[PC1[j] - 1];
        }

        System.out.println();
        System.out.print("CKEY:          ");
        for (int i = 0; i < C.length; i++) {
            System.out.print(C[i] + ", ");
        }

        //Get 24 permuted bit key for D
        for (int j = 28; j < 56; j++) {
            D[j - 28] = newkey[PC1[j] - 1];
        }
        System.out.println();
        System.out.print("DKEY:          ");
        for (int i = 0; i < D.length; i++) {
            System.out.print(D[i] + ", ");
        }

        //Store permuted plaintext into 2 32 arrays, divided left and right
        for (int j = 0; j < 32; j++) {
            left[j] = input[j];
        }

        for (int j = 32; j < 64; j++) {
            right[j - 32] = input[j];
        }

        System.out.println();
        System.out.print("Left:            ");
        for (int i = 0; i < left.length; i++) {
            System.out.print(left[i] + ", ");
        }

        System.out.println();
        System.out.print("Right:           ");
        for (int i = 0; i < right.length; i++) {
            System.out.print(right[i] + ", ");
        }

        //Perform 16 round Robin
        for (int n = 0; n < 16; n++) {
            newright = fFN(right, roundRobin(n, newkey));
            int newleft[] = xor(left, newright);
            left = right; // Rn-1 
            right = newleft;
        } //Ln-1 + f(Rn-1,Kn)
        cyphertext = new int[64];

        //Store and permute Cyphertext for final result
        for (int j = 0; j < 32; j++) {
            cyphertext[j] = right[j];
        }

        for (int j = 0; j < 32; j++) {
            cyphertext[j + 32] = left[j];
        }

        int[] cyphertextperm = new int[64];
        for (int i = 0; i < 64; i++) {
            cyphertextperm[i] = cyphertext[FP[i] - 1];
        }

        System.out.println();
        System.out.print("CypherText:                 ");
        for (int i = 0; i < cyphertextperm.length; i++) {
            System.out.print(cyphertextperm[i] + ", ");
        }
        return cyphertextperm;
    }

    //Left Shift
    public static int[] shift(int[] array, int numShifts) {
        int temp = array[0];
        if (numShifts != 0) {
            for (int i = 0; i < array.length - 1; i++) {
                array[i] = array[i + 1];
            }
            array[array.length - 1] = temp;
            shift(array, numShifts - 1);
        }
        return array;
    }

    //fFN, taken exactly from http://www.pracspedia.com/INS/DES-java.html
    private static int[] fFN(int[] curRight, int[] key) {
        int right[] = new int[48];
        for (int i = 0; i < 48; i++) {
            right[i] = curRight[E[i] - 1];
        }
        int temp[] = xor(right, key);
        int[] newright = S(temp);
        return newright;
    }

    //XOR Code
    private static int[] xor(int[] a, int[] b) {
        int[] xor = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            xor[i] = a[i] ^ b[i];
        }
        return xor;
    }

    //S code, taken and slightly edited from http://www.pracspedia.com/INS/DES-java.html
    private static int[] S(int[] bits) {

        int output[] = new int[32];
        for (int i = 0; i < 8; i++) {
            int row[] = new int[2];
            int column[] = new int[4];
            String sColumn = "";
            String sRow = "";
            row[0] = bits[6 * i];   //get first and last bit for row # of S
            row[1] = bits[(6 * i) + 5];
            for (int k = 0; k < row.length; k++) {
                sRow += row[k];
            }
            column[0] = bits[(6 * i) + 1];  //get middle 4 bits for column # of S
            column[1] = bits[(6 * i) + 2];
            column[2] = bits[(6 * i) + 3];
            column[3] = bits[(6 * i) + 4];

            for (int k = 0; k < column.length; k++) {
                sColumn += column[k];
            }
            int iRow = Integer.parseInt(sRow, 2); //return integer 0-3
            int iColumn = Integer.parseInt(sColumn, 2); //return integer 0-15         
            int x = S[i][(iRow * 16) + iColumn];
            String s = Integer.toBinaryString(x);
            while (s.length() < 4) { //Convert number from Row-Column S to 4 digit binary
                s = "0" + s;
            }
            for (int j = 0; j < 4; j++) {
                output[(i * 4) + j] = Integer.parseInt(s.charAt(j) + "");
            }
        }
        int finalOutput[] = new int[32]; //Permute S-block output
        for (int i = 0; i < 32; i++) {
            finalOutput[i] = output[P[i] - 1];
        }
        return finalOutput;
    }

    //Used for displaying arrays
    private static void display(int x[]) {
        int y[] = new int[x.length];
        y = x;
        for (int i = 0; i < y.length; i++) {
            System.out.print(y[i] + ", ");
        }
        System.out.println();

    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        int[] des = new int[64];
        int[] ecb1 = new int[16];
        int[] ecb2 = new int[16];
        int[] cbc1 = new int[16];
        int[] cbc2 = new int[16];
        String plaintext2 = "I LOVE SECURITY", plaintext3 = "I LOVE SECURITY", plaintext4 = "SECURITYSECURITY", plaintext5 = "I LOVE SECURITY";
        String key2 = "ABCDEFGH", key3 = "ABCDEFGH", IV = "ABCDEFGH";
        int[] plaintext = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1,
            0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};

        int[] key = {0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
            0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0,
            1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 0, 0, 0, 1};

        des = DES(plaintext, key);
        ecb1 = ECB(plaintext2, key2);
        ecb2 = ECB(plaintext5, key2);
        cbc1 = CBC(plaintext3, key3, IV);
        cbc2 = CBC(plaintext4, key3, IV);

        System.out.println();
        System.out.println();
        System.out.println("*******Final Answers*******");
        System.out.print("DES: ");
        display(des);
        System.out.print("ECB1: ");
        display(ecb1);
        System.out.print("ECB2: ");
        display(ecb2);
        System.out.print("CBC1: ");
        display(cbc1);
        System.out.print("CBC2: ");
        display(cbc2);

    }

}
