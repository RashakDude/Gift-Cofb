package org.example;

import java.util.Arrays;

public class GiftComb {

    private static final int CRYPTO_ABYTES = 16;

    private static final long[] RC = {
            0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
            0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
            0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
            0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
    };

    public static long rowperm (long S, long B0_pos, long B1_pos, long B2_pos, long B3_pos) {

        long T = 0;
        for (long b = 0; b < 8; b++) {
            T |= (((S >>> (4 * b)) & 0x1) << (b + 8 * B0_pos));
            T |= (((S >>> (4 * b + 1)) & 0x1) << (b + 8 * B1_pos));
            T |= (((S >>> (4 * b + 2)) & 0x1) << (b + 8 * B2_pos));
            T |= (((S >>> (4 * b + 3)) & 0x1) << (b + 8 * B3_pos));
        }
        return T;

    }

    public static void giftb128 (long[] P, long[] K, long[] C) {

        long T;
        long T6, T7;
        long[] S = new long[4];
        long[] W = new long[8];

        for (int i = 0; i < 4; i++) {
            S[i] = ((P[4*i] << 24) | (P[4*i + 1] << 16) | (P[4*i + 2] << 8) | (P[4*i + 3]));
        }

        for (int i = 0; i < 8; i++) {
            W[i] = ((K[2*i] << 8) | K[2*i + 1]);
        }


        for (int round=0; round<40; round++) {

            S[1] ^= ((S[0] & S[2]));
            S[0] ^= ((S[1] & S[3]));
            S[2] ^= ((S[0] | S[1]));
            S[3] ^= (S[2]);
            S[1] ^= (S[3]);
            S[3] ^= (0xFF);
            S[2] ^= ((S[0] & S[1]));

            T = S[0];
            S[0] = S[3];
            S[3] = T;


            /*===PermBits===*/
            S[0] = rowperm (S[0], 0, 3, 2, 1);
            S[1] = rowperm (S[1], 1, 0, 3, 2);
            S[2] = rowperm (S[2], 2, 1, 0, 3);
            S[3] = rowperm (S[3], 3, 2, 1, 0);

            /*===AddRoundKey===*/
            S[2] ^= ((W[2] << 16) | W[3]);
            S[1] ^= ((W[6] << 16) | W[7]);

            /*Add round constant*/
            S[3] ^= (0x80 ^ RC[round]);

            /*===Key state update===*/
            T6 = ((W[6] >>> 2) | ((W[6] << 14)));
            T7 = ((W[7] >>> 12) | ((W[7] << 4)));
            W[7] = W[5];
            W[6] = W[4];
            W[5] = W[3];
            W[4] = W[2];
            W[3] = W[1];
            W[2] = W[0];
            W[1] = T7;
            W[0] = T6;
        }

        for (int i = 0; i < 4; i++) {
            C[4*i] = ((S[i] >>> 24));
            C[4*i+1] = ((S[i] >>> 16));
            C[4*i+2] = ((S[i] >>> 8));
            C[4*i+3] = (S[i]);
        }

    }

    public static void padding (long[] d, long[] s, int bytes) {

        long[] temp = new long[16];

        if (bytes == 0) {
            for (int i = 0; i < 16; i++) temp[i] = 0;
            temp[0] = 0x80;
        } else if (bytes < 16) {
            System.arraycopy(s, 0, temp, 0, bytes);
            temp[bytes] = 0x80;
            for (int i = bytes + 1; i < 16; i++) temp[i] = 0;
        } else {
            System.arraycopy(s, 0, temp, 0, 16);
        }

        System.arraycopy(temp, 0, d, 0, 16);
    }

    public static void xor_block (long[] d, long[] s1, long[] s2, long bytes) {
        for (int i = 0; i < bytes; i++) d[i] = ((s1[i] ^ s2[i]));
    }

    public static void xor_top_block (long[] d, long[] s1, long[] s2) {
        long[] temp = new long[16];
        for (int i = 0; i < 8; i++) temp[i] = ((s1[i] ^ s2[i]));
        System.arraycopy(s1, 8, temp, 8, 8);
        System.arraycopy(temp, 0, d, 0, 16);
    }

    public static void double_half_block (long[] d, long[] s) {
        long[] temp = new long[8];
        for (int i = 0; i < 7; i++) temp[i] = ((s[i] << 1) | (s[i+1] >>> 7));
        temp[7] = ((s[7] << 1) ^ ((s[0] >>> 7) * 27));
        System.arraycopy(temp, 0, d, 0, 8);
    }

    public static void triple_half_block (long[] d, long[] s) {
        long[] temp = new long[8];
        double_half_block(temp, s);
        for (int i = 0; i < 8; i++) d[i] = ((s[i] ^ temp[i]));
    }

    public static void get (long[] d, long[] s) {
        long[] temp = new long[16];
        System.arraycopy(s, 8, temp, 0, 8);
        for (int i = 0; i < 8; i++) temp[8+i] = ((s[i] << 1) | (s[(i+1)%8] >>> 7));
        System.arraycopy(temp, 0, d, 0, 16);
    }

    public static void phohelper (long[] d, long[] Y, long[] M, int bytes) {
        long[] temp = new long[16];
        get(Y, Y);
        padding(temp, M, bytes);
        xor_block(d, Y, temp, 16);
    }

    public static void phomain (long[] Y, long[] M, long[] X, long[] C, int bytes) {
        xor_block(C, Y, M, bytes);
        phohelper(X, Y, M, bytes);
    }

    public static void phoprime (long[] Y, long[] C, long[] X, long[] M, int bytes) {
        xor_block(M, Y, C, bytes);
        phohelper(X, Y, M, bytes);
    }

    public static long helper (long[] output, long[] msg, long[] ad, long[] nonce, long[] key, Boolean check) {

        int inlen;
        inlen = msg.length;
        int adlen;
        adlen = ad.length;

        if (!check) {
            if (inlen < CRYPTO_ABYTES) return -1;
            inlen -= CRYPTO_ABYTES;
        }

        long emptyA = 0, emptyM = 0;
        if (adlen == 0) emptyA = 1;
        if (inlen == 0) emptyM = 1;

        long[] Y = new long[16];
        long[] input = new long[16];
        long[] offset = new long[8];

        System.arraycopy(nonce, 0, input, 0, 16);
        giftb128(input, key, Y);
        System.arraycopy(Y, 0, offset, 0, 8);

        while (adlen > 16) {
            phohelper(input, Y, ad, 16);
            double_half_block(offset, offset);
            xor_top_block(input, input, offset);
            giftb128(input, key, Y);
            ad = Arrays.copyOfRange(ad, 16, ad.length);
            adlen = adlen - 16;
        }

        triple_half_block(offset, offset);
        if ( emptyA == 1 || (adlen % 16) != 0) {
            triple_half_block(offset, offset);
        }
        if (emptyM == 1) {
            triple_half_block(offset, offset);
            triple_half_block(offset, offset);
        }

        phohelper(input, Y, ad, adlen);
        xor_top_block(input, input, offset);
        giftb128(input, key, Y);

        while (inlen > 16) {
            double_half_block(offset, offset);
            if (check) {
                phomain(Y, msg, input, output, 16);
            } else {
                phoprime(Y, msg, input, output, 16);
            }
            xor_top_block(input, input, offset);
            giftb128(input, key, Y);
            msg = Arrays.copyOfRange(msg, 16, msg.length);
            output = Arrays.copyOfRange(output, 16, output.length);
            System.out.println(output.length);
            inlen = inlen - 16;
        }

        if (emptyM == 0) {
            triple_half_block(offset, offset);
            if (inlen % 16 != 0) {
                triple_half_block(offset, offset);
            }
            if (check) {
                phomain(Y, msg, input, output, inlen);
                output = Arrays.copyOfRange(output, inlen, output.length);
                System.out.println(output.length);
            } else {
                phoprime(Y, msg, input, output, inlen);
                msg = Arrays.copyOfRange(msg, inlen, msg.length);
                System.out.println(msg.length);
            }
            xor_top_block(input, input, offset);
            giftb128(input, key, Y);
        }

        if (check) {
            output = Arrays.copyOf(output, output.length + CRYPTO_ABYTES);
            System.arraycopy(Y, 0, output, output.length - CRYPTO_ABYTES, CRYPTO_ABYTES);
            return 0;
        } else {
            return (Arrays.equals(Arrays.copyOfRange(msg, 0, CRYPTO_ABYTES), Arrays.copyOfRange(Y, 0, CRYPTO_ABYTES)) ? 0 : -1);
        }
    }

    public static long[] crypto_aead_decrypt(long[] msg, long[] ad, long[] nonce, long[] key) {
        long[] output = new long[msg.length - CRYPTO_ABYTES];
        helper(output, msg, ad, nonce, key, Boolean.FALSE);
        return output;
    }

    public static long[] crypto_aead_encrypt(long[] msg, long[] ad, long[] nonce, long[] key) {
        long[] output = new long[msg.length + CRYPTO_ABYTES];
        helper(output, msg, ad, nonce, key, Boolean.TRUE);
        return output;
    }

    public static void main(String[] args) {

        long[] msg = new long[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        long[] ad = new long[] {};
        long[] nonce = new long[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        long[] key = new long[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

        long[] encrypted = crypto_aead_encrypt(msg, ad, nonce, key);
        long[] decrypted = crypto_aead_decrypt(encrypted, ad, nonce, key);
        for (int i = 0; i < encrypted.length; i++) encrypted[i] &= 0xff;
        System.out.print("Encrypted text is: ");
        for(long b: encrypted) {
            System.out.print(Integer.toHexString((int) b));
        }
        System.out.println();
        for (int i = 0; i < decrypted.length; i++) decrypted[i] &= 0xff;
        System.out.println("Decrypted text is: ");
        for(long b: decrypted) {
            System.out.print(Integer.toHexString((int) b));
        }
        System.out.println();

    }

}
