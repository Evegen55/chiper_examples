package chipers;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.testng.Assert.*;


public class FileEncrypterDecrypterTest {

    String originalContent = "foobar";
    String fileName = "baz.enc";

    FileEncrypterDecrypter fileEncrypterDecrypter;

    /**
     * init main encrypt/decrypt entity
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    @BeforeClass
    public void setUp()
            throws NoSuchAlgorithmException,
                   NoSuchPaddingException
    {
        final FileEncrypterDecrypter.AvailableCiphers availableCipher = FileEncrypterDecrypter.AvailableCiphers.AES_CBC_PKCS5Padding;
        final SecretKey secretKey = KeyGenerator.getInstance(availableCipher.getCipherType()).generateKey();
        fileEncrypterDecrypter = new FileEncrypterDecrypter(secretKey, availableCipher.getCipherName());
    }

    @AfterClass
    public void afterClass() {
        new File(fileName).delete(); // cleanup
    }

    @Test
    public void testEncrypt()
            throws IOException,
                   InvalidKeyException
    {
        fileEncrypterDecrypter.encrypt(originalContent, fileName);//produces a file
        assertTrue(new File(fileName).exists());
    }

    @Test(dependsOnMethods = {"testEncrypt"})
    public void testDecrypt()
            throws InvalidAlgorithmParameterException,
                   InvalidKeyException,
                   IOException
    {
        String decryptedContent = fileEncrypterDecrypter.decrypt(fileName);
        assertEquals(originalContent, decryptedContent);
    }

    @Test
    public void testRun() {
    }
}