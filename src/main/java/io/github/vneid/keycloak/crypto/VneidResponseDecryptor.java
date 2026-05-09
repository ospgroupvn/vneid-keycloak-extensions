package io.github.vneid.keycloak.crypto;

import org.keycloak.models.IdentityProviderModel;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Decrypts encrypted responses from VNeID token endpoint.
 *
 * <p>Encryption scheme (per VNeID sample code):</p>
 * <ul>
 *   <li>Response contains {"data": "&lt;base64&gt;", "key": "&lt;base64&gt;"}
 *   <li>RSA/ECB/PKCS1Padding decrypts the key to get AES secret
 *   <li>AES (ECB mode, no IV) decrypts data directly — no IV extraction
 * </ul>
 *
 * <p><strong>Security Note on AES-ECB:</strong></p>
 * <p>AES in ECB mode is cryptographically weaker than CBC/GCM modes because identical
 * plaintext blocks produce identical ciphertext blocks. However, VNeID's specification
 * mandates ECB mode, and this implementation must comply with the VNeID encryption scheme.
 * This is a known limitation imposed by the VNeID identity provider, not a design choice.
 * Compensating controls: ensure TLS 1.2+ for all VNeID communications and restrict
 * network access to VNeID endpoints.</p>
 *
 * @see <a href="https://csrc.nist.gov/publications/detail/sp/800-38a/final">NIST SP 800-38A (ECB mode)</a>
 */
public class VneidResponseDecryptor {

    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String AES_TRANSFORMATION = "AES"; // ECB mode, no IV
    private static final String AES_KEY_ALGORITHM = "AES";

    private final PrivateKey privateKey;
    private final ObjectMapper objectMapper;

    public VneidResponseDecryptor(String privateKeyPem) {
        this.privateKey = parsePrivateKey(privateKeyPem);
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Decrypts an encrypted VNeID response.
     *
     * @param encryptedResponse the raw response body containing data and key fields
     * @return decrypted JSON as a Map
     * @throws RuntimeException if decryption fails
     */
    public Map<String, Object> decrypt(String encryptedResponse) {
        try {
            JsonNode rootNode = objectMapper.readTree(encryptedResponse);

            if (!rootNode.has("data") || !rootNode.has("key")) {
                throw new IllegalArgumentException("Encrypted response must contain 'data' and 'key' fields");
            }

            byte[] encryptedData = Base64.getDecoder().decode(rootNode.get("data").asText());
            byte[] encryptedKey = Base64.getDecoder().decode(rootNode.get("key").asText());

            // Step 1: Decrypt the AES key using RSA private key
            byte[] aesKeyBytes = rsaDecrypt(encryptedKey);

            // Step 2: Decrypt the data using AES
            byte[] decryptedData = aesDecrypt(encryptedData, aesKeyBytes);

            // Step 3: Parse as JSON
            @SuppressWarnings("unchecked")
            Map<String, Object> result = objectMapper.readValue(decryptedData, Map.class);
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt VNeID response", e);
        }
    }

    /**
     * Decrypts data using RSA private key with RSA/ECB/PKCS1Padding.
     */
    private byte[] rsaDecrypt(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Decrypts data using AES (ECB mode, no IV) — per VNeID sample code.
     * The entire encryptedData is decrypted directly without IV extraction.
     */
    private byte[] aesDecrypt(byte[] encryptedData, byte[] aesKeyBytes) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, AES_KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8 format).
     */
    private PrivateKey parsePrivateKey(String pem) {
        try {
            String cleaned = pem
                .replaceAll("-----BEGIN[^-]*-----", "")
                .replaceAll("-----END[^-]*-----", "")
                .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(cleaned);

            // Try PKCS#8 first
            try {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            } catch (Exception ignored) {
                // Fall through to PKCS#1
            }

            // PKCS#1: wrap in PKCS#8 structure
            // PKCS#8 wraps PKCS#1 with: SEQUENCE { SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }, OCTET STRING { pkcs1Bytes } }
            byte[] pkcs8Header = new byte[]{
                0x30, (byte) 0x82, 0, 0,  // SEQUENCE (length placeholder)
                0x02, 0x01, 0x00,          // INTEGER 0 (version)
                0x30, 0x0d,                // SEQUENCE
                0x06, 0x09,                // OID
                0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,  // rsaEncryption
                0x05, 0x00,                // NULL
                0x04, (byte) 0x82, 0, 0    // OCTET STRING (length placeholder)
            };
            int totalLen = pkcs8Header.length - 4 + keyBytes.length;
            byte[] pkcs8 = new byte[pkcs8Header.length + keyBytes.length];
            System.arraycopy(pkcs8Header, 0, pkcs8, 0, pkcs8Header.length);
            System.arraycopy(keyBytes, 0, pkcs8, pkcs8Header.length, keyBytes.length);
            // Fix lengths
            pkcs8[2] = (byte) ((totalLen >> 8) & 0xff);
            pkcs8[3] = (byte) (totalLen & 0xff);
            pkcs8[pkcs8Header.length - 2] = (byte) ((keyBytes.length >> 8) & 0xff);
            pkcs8[pkcs8Header.length - 1] = (byte) (keyBytes.length & 0xff);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid private key format", e);
        }
    }
}
