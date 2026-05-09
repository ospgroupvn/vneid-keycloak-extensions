package io.github.vneid.keycloak.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for VNeID response decryption.
 */
class VneidResponseDecryptorTest {

    private static final String TEST_JSON = "{\"sub\":\"123456789\",\"name\":\"Test User\",\"email\":\"test@example.com\"}";

    private KeyPair rsaKeyPair;
    private byte[] aesKey;

    @BeforeEach
    void setUp() throws Exception {
        // Generate RSA key pair for testing
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        rsaKeyPair = rsaGen.generateKeyPair();

        // Generate AES key (256 bits)
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(256);
        aesKey = aesGen.generateKey().getEncoded();
    }

    @Test
    void testDecrypt_validEncryptedResponse_returnsDecryptedMap() throws Exception {
        // Encrypt the test JSON with AES (ECB mode, no IV — per VNeID sample code)
        byte[] jsonBytes = TEST_JSON.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // AES encrypt with ECB mode (no IV)
        Cipher aesCipher = Cipher.getInstance("AES");
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
        byte[] encrypted = aesCipher.doFinal(jsonBytes);

        // RSA encrypt the AES key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        byte[] encryptedKey = rsaCipher.doFinal(aesKey);

        String encryptedData = Base64.getEncoder().encodeToString(encrypted);
        String encryptedKeyStr = Base64.getEncoder().encodeToString(encryptedKey);

        String response = String.format("{\"data\":\"%s\",\"key\":\"%s\"}", encryptedData, encryptedKeyStr);

        // Get PEM format of private key
        String privateKeyPem = getPrivateKeyPem(rsaKeyPair.getPrivate());

        VneidResponseDecryptor decryptor = new VneidResponseDecryptor(privateKeyPem);
        Map<String, Object> result = decryptor.decrypt(response);

        assertThat(result).containsEntry("sub", "123456789");
        assertThat(result).containsEntry("name", "Test User");
        assertThat(result).containsEntry("email", "test@example.com");
    }

    @Test
    void testDecrypt_missingDataField_throwsException() throws Exception {
        String response = "{\"key\":\"abc\"}";
        String privateKeyPem = getPrivateKeyPem(rsaKeyPair.getPrivate());

        VneidResponseDecryptor decryptor = new VneidResponseDecryptor(privateKeyPem);

        assertThatThrownBy(() -> decryptor.decrypt(response))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to decrypt");
    }

    @Test
    void testDecrypt_missingKeyField_throwsException() throws Exception {
        String response = "{\"data\":\"abc\"}";
        String privateKeyPem = getPrivateKeyPem(rsaKeyPair.getPrivate());

        VneidResponseDecryptor decryptor = new VneidResponseDecryptor(privateKeyPem);

        assertThatThrownBy(() -> decryptor.decrypt(response))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to decrypt");
    }

    @Test
    void testDecrypt_invalidPrivateKeyPem_throwsException() {
        assertThatThrownBy(() -> new VneidResponseDecryptor("invalid-pem"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid private key format");
    }

    private String getPrivateKeyPem(PrivateKey privateKey) throws Exception {
        byte[] encoded = privateKey.getEncoded();
        String base64 = Base64.getEncoder().encodeToString(encoded);

        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        // Split into 64-char lines
        int idx = 0;
        while (idx < base64.length()) {
            int end = Math.min(idx + 64, base64.length());
            sb.append(base64, idx, end).append("\n");
            idx = end;
        }
        sb.append("-----END PRIVATE KEY-----");
        return sb.toString();
    }
}
