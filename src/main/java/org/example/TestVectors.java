package org.example;

import java.io.FileWriter;
import java.io.IOException;

public class TestVectors {
    private static final int MAX_MESSAGE_LENGTH = 32;
    private static final int MAX_ASSOCIATED_DATA_LENGTH = 32;

    private static final int CRYPTO_KEYBYTES = 16;
    private static final int CRYPTO_NPUBBYTES = 16;

    // Write the file name
    private static String file_name = "LWC_AEAD_KAT_128.txt";

    static final String digits = "0123456789ABCDEF";
    static String integerToHex(int input) {
        if (input <= 0)
            return "00";
        StringBuilder hex = new StringBuilder();
        while (input > 0) {
            int digit = input % 16;
            hex.insert(0, digits.charAt(digit));
            input = input / 16;
        }
        if(hex.length() == 1) {
            hex.append("0");
            hex.reverse();
        }
        return hex.toString();
    }

    public static String convertToHexString(long[] input) {
        String temp = "";
        for (int i = 0; i < input.length; i++) {
            temp += integerToHex((int) input[i]);
        }
        return temp;
    }

    public static void main(String args[]) {
        try {

            FileWriter myWriter = new FileWriter(file_name);

            int count = 0;

            for (int mlen = 0; mlen <= MAX_MESSAGE_LENGTH; mlen++) {
                for (int adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {

                    count += 1;

                    long[] key = new long[CRYPTO_KEYBYTES];
                    long[] nonce = new long[CRYPTO_NPUBBYTES];
                    long[] msg = new long[mlen];
                    long[] ad = new long[adlen];

                    for (int i = 0; i < CRYPTO_KEYBYTES; i++) {
                        key[i] = (i % 256);
                    }
                    for (int i = 0; i < CRYPTO_NPUBBYTES; i++) {
                        nonce[i] = (i % 256);
                    }
                    for (int i = 0; i < mlen; i++) {
                        msg[i] = (i % 256);
                    }
                    for (int i = 0; i < adlen; i++) {
                        ad[i] = (i % 256);
                    }

                    String original_message = convertToHexString(msg);
                    System.out.println("Original Message = " + original_message);

                    myWriter.write("Count = " + count + "\n");
                    myWriter.write("Key = " + convertToHexString(key) + "\n");
                    myWriter.write("Nonce = " + convertToHexString(nonce) + "\n");
                    myWriter.write("PT = " + convertToHexString(msg) + "\n");
                    myWriter.write("AD = " + convertToHexString(ad) + "\n");

                    long[] ct = GiftComb.crypto_aead_encrypt(msg, ad, nonce, key);
                    myWriter.write("CT = " + convertToHexString(ct) + "\n");
                    long[] dct = GiftComb.crypto_aead_decrypt(ct, ad, nonce, key);
                    String decrypted_text = convertToHexString(dct);

                    System.out.println("Decrypted Message = " + decrypted_text);

                    if (!(decrypted_text.equals(original_message))) {
                        myWriter.write("Error: crypto_aead_decrypt did not recover the plaintext \n");
                    }
                    myWriter.write("\n");
                }
            }

            myWriter.close();
            System.out.println("Successfully wrote to the file.");

        } catch (IOException e) {

            System.out.println("An error occurred.");
            e.printStackTrace();

        }
    }
}