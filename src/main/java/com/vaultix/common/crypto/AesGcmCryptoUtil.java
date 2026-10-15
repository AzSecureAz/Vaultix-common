package com.vaultix.common.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcmCryptoUtil {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private AesGcmCryptoUtil() {
    }

    public static SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(AES_KEY_SIZE_BITS, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to generate AES key", e);
        }
    }

    public static String generateKeyAsBase64() {
        return Base64.getEncoder().encodeToString(generateKey().getEncoded());
    }

    public static SecretKey toSecretKey(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalArgumentException("Encryption key must not be null or blank");
        }
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        if (decodedKey.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes (256 bits). Found: " + decodedKey.length);
        }
        return new SecretKeySpec(decodedKey, ALGORITHM);
    }

    public static String encrypt(String plaintext, String base64Key) {
        if (plaintext == null) {
            return null;
        }
        return encrypt(plaintext, toSecretKey(base64Key));
    }

    public static String encrypt(String plaintext, SecretKey key) {
        if (plaintext == null) {
            return null;
        }
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = encrypt(plaintextBytes, key);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static byte[] encrypt(byte[] plaintext, SecretKey key) {
        if (plaintext == null) {
            return null;
        }
        if (key == null) {
            throw new IllegalArgumentException("SecretKey must not be null");
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] ciphertext = cipher.doFinal(plaintext);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
            byteBuffer.put(iv);
            byteBuffer.put(ciphertext);
            return byteBuffer.array();
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Failed to encrypt data with AES-GCM", e);
        }
    }

    public static String decrypt(String base64EncryptedData, String base64Key) {
        if (base64EncryptedData == null) {
            return null;
        }
        return decrypt(base64EncryptedData, toSecretKey(base64Key));
    }

    public static String decrypt(String base64EncryptedData, SecretKey key) {
        if (base64EncryptedData == null) {
            return null;
        }
        byte[] encryptedBytes = Base64.getDecoder().decode(base64EncryptedData);
        byte[] decryptedBytes = decrypt(encryptedBytes, key);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey key) {
        if (encryptedData == null) {
            return null;
        }
        if (key == null) {
            throw new IllegalArgumentException("SecretKey must not be null");
        }
        if (encryptedData.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
            throw new IllegalArgumentException("Encrypted data is too short to contain a valid IV and GCM auth tag");
        }
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            byteBuffer.get(iv);

            byte[] ciphertext = new byte[byteBuffer.remaining()];
            byteBuffer.get(ciphertext);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Failed to decrypt data or authentication tag verification failed", e);
        }
    }
}
