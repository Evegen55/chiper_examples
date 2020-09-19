package chipers;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public final class FileEncrypterDecrypter {

    private final SecretKey secretKey;
    private final Cipher cipher;

    FileEncrypterDecrypter(final SecretKey secretKey, final String cipher)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.secretKey = secretKey;
        this.cipher = Cipher.getInstance(cipher);
    }

    /**
     * @see sun.security.pkcs11.SunPKCS11
     */
    enum AvailableCiphers {
        AES_CBC_PKCS5Padding("AES/CBC/PKCS5Padding", "AES");

        private final String cipherName;
        private final String cipherType;

        AvailableCiphers(final String cipherName, final String cipherType) {
            this.cipherName = cipherName;
            this.cipherType = cipherType;
        }

        public String getCipherName() {
            return cipherName;
        }

        public String getCipherType() {
            return cipherType;
        }
    }

    /**
     * Encrypts string in accordance with Cipher, then stores it into a file with given system-dependent filename
     *
     * @param content
     * @param fileName
     * @throws InvalidKeyException
     * @throws IOException
     */
    public void encrypt(final String content, final String fileName) throws InvalidKeyException, IOException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        /*
         * Returns the initialization vector (IV) in a new buffer, or null if the
         * underlying algorithm does not use an IV, or if the IV has not yet
         * been set.
         *
         * This is useful in the case where a random IV was created,
         * or in the context of password-based encryption or
         * decryption, where the IV is derived from a user-supplied password.

         */
        byte[] iv = cipher.getIV();

        try (final FileOutputStream fileOut = new FileOutputStream(fileName);
             final CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
            fileOut.write(iv);
            cipherOut.write(content.getBytes());
        }
    }

    /**
     * Decrypts file into a String which previously has been encrypted with given secret key.
     *
     * @param fileName
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IOException
     */
    public String decrypt(final String fileName) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        try (final FileInputStream fileInputStream = new FileInputStream(fileName)) {
            byte[] fileIv = new byte[16];
            fileInputStream.read(fileIv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(fileIv));

            try (final CipherInputStream cipherIn = new CipherInputStream(fileInputStream, cipher);
                 final InputStreamReader inputReader = new InputStreamReader(cipherIn);
                 final BufferedReader reader = new BufferedReader(inputReader)
            ) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                return sb.toString();
            }
        }
    }

    public void run() {
        try {
            String text = "Hello World";
            String key = "Bar12345Bar12345"; // 128 bit key
            // Create key and cipher
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            // encrypt the text
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encrypted = cipher.doFinal(text.getBytes());
            System.err.println(new String(encrypted));
            // decrypt the text
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            String decrypted = new String(cipher.doFinal(encrypted));
            System.err.println(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

