package com.example.cipherbugsample;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * This sample demonstrates an issue in the AOSP code when using a {@link Cipher}'s {@link Cipher#doFinal()}
 * method with various input sizes while performing AES transformation in GCM.
 * <p>
 * When using a sufficiently large plaintext value (4073 bytes or larger), using the {@link Cipher#doFinal()}
 * method (or it's overloads) without previously chunking the data results in an {@link IllegalBlockSizeException}
 * during the encryption operation.
 * <p>
 * The {@link IllegalBlockSizeException} also presents itself during decryption, though this sample
 * does not make assertions about the size of ciphertext required.
 * <p>
 * The impact of this bug is that it is impossible to use {@link javax.crypto.CipherInputStream}
 * and {@link javax.crypto.CipherOutputStream} with AES in GCM. Based on limited debugging, it appears
 * that the stream implementation in AOSP buffers the input and then calls {@link Cipher#doFinal()}
 * at the end.
 * <p>
 * This bug has been confirmed on Android emulators running API 27 and 26. On API 25 this bug is not present.
 * <p>
 * A workaround for the issue is presented. By chunking the input data and calling {@link Cipher#update(byte[])}
 * with the chunks, one is able to reduce the input to manageable sizes and avoid the {@link IllegalBlockSizeException}.
 * However, this workaround requires manually handling a byte array, making it impossible to use {@link javax.crypto.CipherInputStream}
 * and {@link javax.crypto.CipherOutputStream}.
 */
@RunWith(Parameterized.class)
public class CryptoSample {

    // Using 4072 cleartext bytes is ok, but using 4073 or higher produces an error during decryption
    @Parameterized.Parameters(name = "{index}: plaintextBytes:{0}")
    public static Iterable<Integer> parameters() {
        return Arrays.asList(4072, 4073);
    }

    private final int lengthOfPlaintext;

    public CryptoSample(int lengthOfPlaintext) {
        this.lengthOfPlaintext = lengthOfPlaintext;
    }

    /**
     * Will produces a {@link IllegalBlockSizeException} when the bug is encountered
     */
    @Test
    public void encryptUsingDoFinal() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, IOException {
        Key key = generateAesKey();

        // GCM uses a 12-byte nonce
        byte[] iv = generateRandomBytes(12);
        GCMParameterSpec algorithmSpec = new GCMParameterSpec(128, iv);

        // Using 4072 cleartext bytes is ok, but using 4073 produces an error during decryption
        byte[] plainText = generateRandomBytes(lengthOfPlaintext);

        // Perform the encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
        cipher.doFinal(plainText);
    }

    /**
     * Will produces a {@link IllegalBlockSizeException} when the bug is encountered
     */
    @Test
    public void encryptUsingBufferedWorkaround_decryptUsingDoFinal() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, IOException {
        Key key = generateAesKey();

        // GCM uses a 12-byte nonce
        byte[] iv = generateRandomBytes(12);
        GCMParameterSpec algorithmSpec = new GCMParameterSpec(128, iv);

        // Using 4072 cleartext bytes is ok, but using 4073 produces an error during decryption
        byte[] plainText = generateRandomBytes(lengthOfPlaintext);

        // Perform the encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
        byte[] cipherText = readAndProcessBytes(cipher, plainText);

        // Perform the decryption
        cipher.init(Cipher.DECRYPT_MODE, key, algorithmSpec);
        cipher.doFinal(cipherText);
    }

    /**
     * Will always pass
     */
    @Test
    public void encryptAndDecryptUsingBufferedWorkaround() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Key key = generateAesKey();

        // GCM uses a 12-byte nonce
        byte[] iv = generateRandomBytes(12);
        GCMParameterSpec algorithmSpec = new GCMParameterSpec(128, iv);

        byte[] plainText = generateRandomBytes(lengthOfPlaintext);

        // Perform the encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
        byte[] cipherText = readAndProcessBytes(cipher, plainText);

        // Perform the decryption
        cipher.init(Cipher.DECRYPT_MODE, key, algorithmSpec);
        readAndProcessBytes(cipher, cipherText);
    }

    /**
     * Generate an AES key for encryption and decryption
     */
    private SecretKey generateAesKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        KeyGenParameterSpec parameterSpec = new KeyGenParameterSpec.Builder("KeyAlias", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)

                // GCM mode should not be using random IVs
                .setRandomizedEncryptionRequired(false)
                .setKeySize(256)
                .build();
        keyGenerator.init(parameterSpec);
        return keyGenerator.generateKey();
    }

    /**
     * DO NOT USE THIS FOR REAL CRYPTO
     */
    private byte[] generateRandomBytes(int count) throws UnsupportedEncodingException {
        String options = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuilder builder = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            int index = random.nextInt(options.length());
            builder.append(options.charAt(index));
        }
        return builder.toString().getBytes("ASCII");
    }

    private byte[] readAndProcessBytes(Cipher cipher, byte[] source) throws IOException, BadPaddingException, IllegalBlockSizeException {
        ByteArrayOutputStream processed = new ByteArrayOutputStream();
        int offset = 0;
        while (source.length > offset) {
            int lengthToRead = Math.min(2048, source.length - offset);
            byte[] transformed = cipher.update(source, offset, lengthToRead);
            offset += lengthToRead;
            if (transformed != null) {
                processed.write(transformed);
            }
        }
        processed.write(cipher.doFinal());
        return processed.toByteArray();
    }
}
