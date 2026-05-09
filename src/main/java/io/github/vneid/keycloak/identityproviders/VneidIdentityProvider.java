package io.github.vneid.keycloak.identityproviders;

import io.github.vneid.keycloak.crypto.VneidResponseDecryptor;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * VNeID Identity Provider for Keycloak 26.
 *
 * <p>VNeID-specific differences from standard OIDC:</p>
 * <ul>
 *   <li>Token request must be form-urlencoded (not JSON)</li>
 *   <li>Token response body is AES encrypted (ECB mode, no IV): {"data":"&lt;b64&gt;","key":"&lt;b64&gt;"}</li>
 *   <li>Userinfo endpoint also returns encrypted response</li>
 *   <li>No standard JWT id_token — identity built from userinfo claims</li>
 *   <li>Authorization code may be encrypted (AES key RSA-encrypted as encrypt_key)</li>
 * </ul>
 *
 * <p>Configurable claim names (via Identity Provider config properties):</p>
 * <ul>
 *   <li>{@code userinfoUserIdClaim} - claim for user identifier (default: "citizenPid")</li>
 *   <li>{@code userinfoNameClaim} - claim for full name (default: "fullName")</li>
 *   <li>{@code userinfoBirthDateClaim} - claim for birth date (default: "birthDate")</li>
 * </ul>
 */
public class VneidIdentityProvider extends OIDCIdentityProvider {

    /** Config property key for RSA private key PEM. */
    static final String PRIVATE_KEY_CONFIG = "vneidPrivateKey";

    /** Config property key for debug mode toggle. */
    static final String DEBUG_SKIP_TOKEN_CONFIG = "vneidDebugSkipToken";

    /** Config property key for user ID claim name. */
    static final String USER_ID_CLAIM_CONFIG = "userinfoUserIdClaim";

    /** Config property key for name claim name. */
    static final String NAME_CLAIM_CONFIG = "userinfoNameClaim";

    /** Config property key for birth date claim name. */
    static final String BIRTH_DATE_CLAIM_CONFIG = "userinfoBirthDateClaim";

    /** Default claim name for user identifier. */
    static final String DEFAULT_USER_ID_CLAIM = "citizenPid";

    /** Default claim name for full name. */
    static final String DEFAULT_NAME_CLAIM = "fullName";

    /** Default claim name for birth date. */
    static final String DEFAULT_BIRTH_DATE_CLAIM = "birthDate";

    private final VneidResponseDecryptor decryptor;

    public VneidIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
        this.decryptor = initDecryptor(config);
        logger.infof("VNeID: provider initialized, alias=%s, authUrl=%s, tokenUrl=%s, userinfoUrl=%s",
                config.getAlias(), config.getAuthorizationUrl(), config.getTokenUrl(), config.getUserInfoUrl());
    }

    private VneidResponseDecryptor initDecryptor(OIDCIdentityProviderConfig config) {
        String pem = config.getConfig().get(PRIVATE_KEY_CONFIG);
        if (pem != null && !pem.isBlank()) {
            try {
                VneidResponseDecryptor d = new VneidResponseDecryptor(pem);
                logger.infof("VNeID: RSA private key loaded successfully (PEM length=%d)", pem.length());
                return d;
            } catch (Exception e) {
                logger.errorf(e, "VNeID: Failed to initialize decryptor — encrypted responses will FAIL: %s", e.getMessage());
            }
        } else {
            logger.warnf("VNeID: No RSA private key configured (%s) — encrypted responses will fail", PRIVATE_KEY_CONFIG);
        }
        return null;
    }

    /** Returns a config property value with a default fallback. */
    private String getConfigClaim(String key, String defaultValue) {
        String value = getConfig().getConfig().get(key);
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, BrokeredIdentityContext context) {
        // VNeID does not return a standard OIDC nonce - skip validation
        logger.debugf("VNeID: skipping nonce validation for provider %s (VNeID doesn't return nonce)", getConfig().getProviderId());
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder builder = UriBuilder.fromUri(getConfig().getAuthorizationUrl())
                .queryParam("response_type", "code")
                .queryParam("client_id", getConfig().getClientId())
                .queryParam("redirect_uri", request.getRedirectUri())
                .queryParam("scope", getConfig().getDefaultScope())
                .queryParam("state", request.getState().getEncoded());
        logger.infof("VNeID: createAuthorizationUrl: %s", builder.build().toString());
        return builder;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        boolean isEncrypted = response != null && response.contains("\"data\"") && response.contains("\"key\"");
        logger.infof("VNeID: getFederatedIdentity called, response length=%d, encrypted=%b",
                response == null ? 0 : response.length(), isEncrypted);
        // Debug logging only - response body contains sensitive tokens
        logger.debugf("VNeID: token response body=%s", response);

        String tokenJson = decryptIfNeeded(response);
        try {
            AccessTokenResponse tokenResponse = JsonSerialization.readValue(tokenJson, AccessTokenResponse.class);
            String accessToken = tokenResponse.getToken();
            logger.infof("VNeID: token parsed: access_token present=%b, expires_in=%d, token_type=%s, scope=%s",
                    accessToken != null && !accessToken.isBlank(),
                    tokenResponse.getExpiresIn(),
                    tokenResponse.getTokenType(),
                    tokenResponse.getScope());

            if (accessToken == null || accessToken.isBlank()) {
                logger.errorf("VNeID: token response missing access_token");
                throw new IdentityBrokerException("VNeID token response contains no access_token");
            }

            // VNeID does not return a standard JWT id_token — fetch user info from userinfo endpoint
            String userinfoUrl = getConfig().getUserInfoUrl();
            logger.infof("VNeID: calling userinfo endpoint: %s", userinfoUrl);
            if (userinfoUrl == null || userinfoUrl.isBlank()) {
                throw new IdentityBrokerException("VNeID: userinfo endpoint URL is not configured");
            }

            SimpleHttp.Response userinfoResponse = SimpleHttp.doGet(userinfoUrl, session)
                    .header("Authorization", "Bearer " + accessToken)
                    .asResponse();
            int userinfoStatus = userinfoResponse.getStatus();
            String userinfoRaw = userinfoResponse.asString();
            boolean userinfoEncrypted = userinfoRaw != null && userinfoRaw.contains("\"data\"") && userinfoRaw.contains("\"key\"");
            logger.infof("VNeID: userinfo response: HTTP=%d, encrypted=%b, length=%d",
                    userinfoStatus, userinfoEncrypted, userinfoRaw == null ? 0 : userinfoRaw.length());
            // Debug logging only - userinfo contains PII
            logger.debugf("VNeID: userinfo raw body=%s", userinfoRaw);

            if (userinfoStatus != 200) {
                logger.errorf("VNeID: userinfo FAILED status=%d", userinfoStatus);
                throw new IdentityBrokerException("VNeID userinfo endpoint returned HTTP " + userinfoStatus);
            }

            String userinfoJson = decryptIfNeeded(userinfoRaw);
            // Debug logging only - userinfo contains PII
            logger.debugf("VNeID: userinfo after decrypt=%s", userinfoJson);

            @SuppressWarnings("unchecked")
            Map<String, Object> claims = JsonSerialization.readValue(userinfoJson, Map.class);
            logger.infof("VNeID: userinfo claims keys=%s", claims.keySet());

            // Read claim names from config (with defaults)
            String userIdClaim = getConfigClaim(USER_ID_CLAIM_CONFIG, DEFAULT_USER_ID_CLAIM);
            String nameClaim = getConfigClaim(NAME_CLAIM_CONFIG, DEFAULT_NAME_CLAIM);
            String birthDateClaim = getConfigClaim(BIRTH_DATE_CLAIM_CONFIG, DEFAULT_BIRTH_DATE_CLAIM);

            String userId = (String) claims.get(userIdClaim);
            String fullName = (String) claims.get(nameClaim);
            String birthDate = (String) claims.get(birthDateClaim);
            Object accountType = claims.get("accountType");
            Object accountLevel = claims.get("accountLevel");
            logger.infof("VNeID: parsed user: %s=%s, %s=%s, %s=%s, accountType=%s, accountLevel=%s",
                    userIdClaim, userId != null ? userId.replaceAll("(?<=.{3}).(?=.{3})", "*") : "null",
                    nameClaim, fullName,
                    birthDateClaim, birthDate,
                    accountType, accountLevel);

            if (userId == null || userId.isBlank()) {
                logger.errorf("VNeID: %s missing! Full userinfo JSON=%s", userIdClaim, userinfoJson);
                throw new IdentityBrokerException("VNeID userinfo response missing '" + userIdClaim + "' field");
            }

            BrokeredIdentityContext identity = new BrokeredIdentityContext(userId, getConfig());
            identity.setUsername(userId);
            identity.setName(fullName);
            identity.setIdp(this);
            identity.setToken(accessToken);
            logger.infof("VNeID: BrokeredIdentityContext built OK, id=%s", userId.replaceAll("(?<=.{3}).(?=.{3})", "*"));

            return identity;

        } catch (IOException e) {
            logger.errorf(e, "VNeID: IOException in getFederatedIdentity: %s", e.getMessage());
            throw new IdentityBrokerException("Failed to parse VNeID response: " + e.getMessage(), e);
        }
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new VneidEndpoint(callback, realm, event, this);
    }

    @Override
    protected String getDefaultScopes() {
        return "openid";
    }

    String decryptIfNeeded(String raw) {
        if (raw == null) return null;
        if (decryptor == null) {
            logger.warnf("VNeID: decryptIfNeeded - no decryptor, returning raw as-is");
            return raw;
        }
        if (raw.contains("\"data\"") && raw.contains("\"key\"")) {
            logger.infof("VNeID: decryptIfNeeded - detected encrypted payload, attempting RSA+AES decrypt");
            try {
                Map<String, Object> decrypted = decryptor.decrypt(raw);
                String result = JsonSerialization.writeValueAsString(decrypted);
                logger.infof("VNeID: decryptIfNeeded - SUCCESS, decrypted keys=%s", decrypted.keySet());
                return result;
            } catch (Exception e) {
                logger.errorf(e, "VNeID: decryptIfNeeded - FAILED: %s", e.getMessage());
                logger.errorf("VNeID: encrypted payload (first 300 chars)=%s",
                        raw.length() > 300 ? raw.substring(0, 300) + "..." : raw);
            }
        } else {
            logger.infof("VNeID: decryptIfNeeded - no encryption detected, returning raw (first 100 chars)=%s",
                    raw.length() > 100 ? raw.substring(0, 100) + "..." : raw);
        }
        return raw;
    }

    /**
     * Decrypts an encrypted authorization code using the encrypt_key.
     * VNeID encrypts the authorization code with AES, and the AES key is RSA-encrypted as encrypt_key.
     *
     * @param encryptedCodeBase64 the base64-encoded encrypted authorization code
     * @param encryptKeyBase64 the base64-encoded RSA-encrypted AES key
     * @return the decrypted authorization code (typically a GUID or dot-separated GUIDs)
     */
    String decryptAuthorizationCode(String encryptedCodeBase64, String encryptKeyBase64) {
        if (encryptedCodeBase64 == null || encryptKeyBase64 == null) {
            return encryptedCodeBase64;
        }
        try {
            String pem = getConfig().getConfig().get(PRIVATE_KEY_CONFIG);
            if (pem == null || pem.isBlank()) {
                logger.warnf("VNeID: Cannot decrypt code - no private key configured");
                return encryptedCodeBase64;
            }

            // Parse private key
            String cleaned = pem
                .replaceAll("-----BEGIN[^-]*-----", "")
                .replaceAll("-----END[^-]*-----", "")
                .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(cleaned);

            PrivateKey privateKey;
            try {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                privateKey = java.security.KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            } catch (Exception e) {
                // Try PKCS#1 -> PKCS#8 conversion
                byte[] pkcs8Header = new byte[]{
                    0x30, (byte) 0x82, 0, 0,
                    0x02, 0x01, 0x00,
                    0x30, 0x0d,
                    0x06, 0x09,
                    0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
                    0x05, 0x00,
                    0x04, (byte) 0x82, 0, 0
                };
                int totalLen = pkcs8Header.length - 4 + keyBytes.length;
                byte[] pkcs8 = new byte[pkcs8Header.length + keyBytes.length];
                System.arraycopy(pkcs8Header, 0, pkcs8, 0, pkcs8Header.length);
                System.arraycopy(keyBytes, 0, pkcs8, pkcs8Header.length, keyBytes.length);
                pkcs8[2] = (byte) ((totalLen >> 8) & 0xff);
                pkcs8[3] = (byte) (totalLen & 0xff);
                pkcs8[pkcs8Header.length - 2] = (byte) ((keyBytes.length >> 8) & 0xff);
                pkcs8[pkcs8Header.length - 1] = (byte) (keyBytes.length & 0xff);
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
                privateKey = java.security.KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            }

            // RSA decrypt AES key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.PRIVATE_KEY, privateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptKeyBase64));

            // AES decrypt the code
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decryptedBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedCodeBase64));
            String decryptedCode = new String(decryptedBytes, StandardCharsets.UTF_8);

            logger.infof("VNeID: Decrypted authorization code successfully (length=%d -> %d)",
                    encryptedCodeBase64.length(), decryptedCode.length());
            return decryptedCode;
        } catch (Exception e) {
            logger.errorf(e, "VNeID: Failed to decrypt authorization code: %s", e.getMessage());
            return encryptedCodeBase64;
        }
    }

    public class VneidEndpoint extends AbstractOAuth2IdentityProvider.Endpoint {

        public VneidEndpoint(IdentityProvider.AuthenticationCallback callback,
                             RealmModel realm,
                             EventBuilder event,
                             VneidIdentityProvider provider) {
            super(callback, realm, event, provider);
        }

        /**
         * Override authResponse to extract the raw `code` from the query string
         * before JAX-RS decodes it. JAX-RS converts '+' to space, which breaks
         * VNeID's base64-encoded authorization codes. We parse raw query string manually.
         */
        @GET
        @Override
        public Response authResponse(@QueryParam("state") String state,
                                     @QueryParam("code") String decodedCode,
                                     @QueryParam("error") String error,
                                     @QueryParam("error_description") String errorDescription) {
            // Read raw query string — JAX-RS @QueryParam already URL-decoded '+' to space
            String rawCode = extractRawParam("code");
            String rawEncryptKey = extractRawParam("encrypt_key");
            logger.infof("VNeID: authResponse called — state present=%b, error=%s", state != null, error);
            logger.infof("VNeID: code via @QueryParam (decoded, length=%d)=%s",
                    decodedCode == null ? 0 : decodedCode.length(), decodedCode);
            logger.infof("VNeID: code via raw query string (length=%d)=%s",
                    rawCode == null ? 0 : rawCode.length(), rawCode);
            logger.infof("VNeID: encrypt_key present=%b, length=%d",
                    rawEncryptKey != null, rawEncryptKey == null ? 0 : rawEncryptKey.length());

            // Store encrypt_key in session for later use in token request
            if (rawEncryptKey != null && !rawEncryptKey.isBlank()) {
                session.setAttribute("vneid_encrypt_key", rawEncryptKey);
            }

            // DEBUG MODE: show all code variants on screen for testing
            // WARNING: Debug mode exposes sensitive data (codes, keys, secrets). NEVER enable in production.
            boolean debugSkip = "true".equalsIgnoreCase(getConfig().getConfig().get(DEBUG_SKIP_TOKEN_CONFIG));
            if (debugSkip) {
                logger.error("VNeID: DEBUG MODE IS ENABLED - This should NEVER be used in production! Exposing sensitive authentication data.");
                String codeToUse = (rawCode != null && !rawCode.equals(decodedCode)) ? rawCode : decodedCode;
                String tokenUrl = getConfig().getTokenUrl();
                String clientId = getConfig().getClientId();
                String clientSecret = getConfig().getClientSecret();
                String callbackUrl = session.getContext().getUri().getBaseUri().toString();
                if (callbackUrl.endsWith("/")) callbackUrl = callbackUrl.substring(0, callbackUrl.length() - 1);
                String redirectUri = callbackUrl + "/realms/" + realm.getName() + "/broker/" + getConfig().getAlias() + "/endpoint";

                logger.warnf("========== VNeID DEBUG MODE — TOKEN EXCHANGE SKIPPED ==========");
                logger.warnf("VNeID DEBUG: code (raw)=%s", codeToUse);
                logger.warnf("VNeID DEBUG: encrypt_key present=%b", rawEncryptKey != null);

                String html = "<html><head><meta charset='UTF-8'><title>VNeID Debug</title>"
                        + "<style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:2rem;line-height:1.6;}"
                        + "h2{color:#4ec9b0;margin-top:0;}.label{color:#9cdcfe;}.value{color:#ce9178;word-break:break-all;}"
                        + ".cmd{background:#2d2d2d;padding:1rem;border-radius:4px;overflow-x:auto;margin:0.5rem 0 1rem;position:relative;}"
                        + "code{font-family:'Cascadia Code',monospace;font-size:12px;white-space:pre;}"
                        + ".section{margin:1.5rem 0;padding:1rem;background:#252526;border-radius:4px;}"
                        + ".note{color:#6a9955;font-size:12px;}"
                        + ".copy-btn{position:absolute;top:0.5rem;right:0.5rem;background:#0e639c;color:#fff;border:none;padding:0.3rem 0.8rem;border-radius:3px;cursor:pointer;font-family:monospace;font-size:11px;}"
                        + ".copy-btn:hover{background:#1177bb;}"
                        + ".copy-btn:active{background:#094d7a;}"
                        + ".copied{background:#3c8c60!important;}"
                        + ".code-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;}"
                        + ".code-header h3{margin:0;}</style></head><body>"
                        + "<h2>VNeID Debug Mode — Token Exchange Skipped</h2>"
                        + "<div class='section'>"
                        + "<p><span class='label'>1. Code (raw query string, preserved +):</span><br><span class='value'>" + escapeHtml(codeToUse) + "</span></p>";

                if (rawEncryptKey != null && !rawEncryptKey.isBlank()) {
                    html += "<p><span class='label'>2. Encrypt key (raw):</span><br><span class='value'>" + escapeHtml(rawEncryptKey) + "</span></p>";
                }

                html += "<p><span class='label'>3. Code (decoded by JAX-RS, + thành space):</span><br><span class='value'>" + escapeHtml(decodedCode) + "</span></p>"
                        + "</div>";

                // Test case 1: raw code, form-urlencoded
                String cmd1 = "curl -s -X POST '" + tokenUrl + "' \\\n"
                        + "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                        + "  --data-urlencode 'grant_type=authorization_code' \\\n"
                        + "  --data-urlencode 'client_id=" + clientId + "' \\\n"
                        + "  --data-urlencode 'client_secret=" + clientSecret + "' \\\n"
                        + "  --data-urlencode 'redirect_uri=" + redirectUri + "' \\\n"
                        + "  --data-urlencode 'code=" + codeToUse + "'";
                html += "<div class='section'>"
                        + "<div class='code-header'><h3>Test 1: Raw code (form-urlencoded)</h3>"
                        + "<button class='copy-btn' onclick='copyCmd(this)'>Copy</button></div>"
                        + "<p class='note'>Gửi code raw với --data-urlencode (curl tự encode)</p>"
                        + "<div class='cmd'><code data-cmd='" + escapeAttr(cmd1) + "'>" + escapeHtml(cmd1) + "</code></div></div>";

                // Test case 2: raw code + encrypt_key
                if (rawEncryptKey != null && !rawEncryptKey.isBlank()) {
                    String cmd2 = "curl -s -X POST '" + tokenUrl + "' \\\n"
                            + "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                            + "  --data-urlencode 'grant_type=authorization_code' \\\n"
                            + "  --data-urlencode 'client_id=" + clientId + "' \\\n"
                            + "  --data-urlencode 'client_secret=" + clientSecret + "' \\\n"
                            + "  --data-urlencode 'redirect_uri=" + redirectUri + "' \\\n"
                            + "  --data-urlencode 'code=" + codeToUse + "' \\\n"
                            + "  --data-urlencode 'encrypt_key=" + rawEncryptKey + "'";
                    html += "<div class='section'>"
                            + "<div class='code-header'><h3>Test 2: Raw code + encrypt_key</h3>"
                            + "<button class='copy-btn' onclick='copyCmd(this)'>Copy</button></div>"
                            + "<p class='note'>Gửi kèm encrypt_key theo tài liệu VNeID</p>"
                            + "<div class='cmd'><code data-cmd='" + escapeAttr(cmd2) + "'>" + escapeHtml(cmd2) + "</code></div></div>";
                }

                // Test case 3: URL-encoded code (manually encoded)
                String urlEncodedCode = java.net.URLEncoder.encode(codeToUse, StandardCharsets.UTF_8).replace("+", "%20");
                String cmd3 = "curl -s -X POST '" + tokenUrl + "' \\\n"
                        + "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                        + "  --data 'grant_type=authorization_code&"
                        + "client_id=" + java.net.URLEncoder.encode(clientId, StandardCharsets.UTF_8) + "&"
                        + "client_secret=" + java.net.URLEncoder.encode(clientSecret, StandardCharsets.UTF_8) + "&"
                        + "redirect_uri=" + java.net.URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) + "&"
                        + "code=" + urlEncodedCode + "'";
                html += "<div class='section'>"
                        + "<div class='code-header'><h3>Test 3: URL-encoded code (manually, + thành %20)</h3>"
                        + "<button class='copy-btn' onclick='copyCmd(this)'>Copy</button></div>"
                        + "<p class='note'>Encode code trước, gửi qua --data (không dùng --data-urlencode)</p>"
                        + "<div class='cmd'><code data-cmd='" + escapeAttr(cmd3) + "'>" + escapeHtml(cmd3) + "</code></div></div>";

                // Test case 4: JSON body
                String cmd4 = "curl -s -X POST '" + tokenUrl + "' \\\n"
                        + "  -H 'Content-Type: application/json' \\\n"
                        + "  -d '{\n"
                        + "    \"grant_type\": \"authorization_code\",\n"
                        + "    \"code\": \"" + codeToUse + "\",\n"
                        + "    \"client_id\": \"" + clientId + "\",\n"
                        + "    \"client_secret\": \"" + clientSecret + "\",\n"
                        + "    \"redirect_uri\": \"" + redirectUri + "\"\n"
                        + "  }'";
                html += "<div class='section'>"
                        + "<div class='code-header'><h3>Test 4: JSON body (Content-Type: application/json)</h3>"
                        + "<button class='copy-btn' onclick='copyCmd(this)'>Copy</button></div>"
                        + "<p class='note'>Theo dòng 195 tài liệu VNeID (có thể bị 415)</p>"
                        + "<div class='cmd'><code data-cmd='" + escapeAttr(cmd4) + "'>" + escapeHtml(cmd4) + "</code></div></div>";

                // Test case 5: code with + replaced by %2B
                String percentEncodedCode = codeToUse.replace("+", "%2B");
                String cmd5 = "curl -s -X POST '" + tokenUrl + "' \\\n"
                        + "  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                        + "  --data-urlencode 'grant_type=authorization_code' \\\n"
                        + "  --data-urlencode 'client_id=" + clientId + "' \\\n"
                        + "  --data-urlencode 'client_secret=" + clientSecret + "' \\\n"
                        + "  --data-urlencode 'redirect_uri=" + redirectUri + "' \\\n"
                        + "  --data-urlencode 'code=" + percentEncodedCode + "'";
                html += "<div class='section'>"
                        + "<div class='code-header'><h3>Test 5: Code với + thay bằng %2B</h3>"
                        + "<button class='copy-btn' onclick='copyCmd(this)'>Copy</button></div>"
                        + "<p class='note'>Thay + bằng %2B trước khi gửi</p>"
                        + "<div class='cmd'><code data-cmd='" + escapeAttr(cmd5) + "'>" + escapeHtml(cmd5) + "</code></div></div>";

                html += "<script>function copyCmd(btn){var cmd=btn.closest('.section').querySelector('code').getAttribute('data-cmd');navigator.clipboard.writeText(cmd).then(function(){btn.textContent='Copied!';btn.classList.add('copied');setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},1500);}).catch(function(){btn.textContent='Failed';});}</script>"
                        + "<div class='section'><p class='note'>Chạy lần lượt từng test, code chỉ sống vài giây. Nếu tất cả 401 → liên hệ VNeID support (nghi IP whitelist).</p></div>"
                        + "</body></html>";

                return Response.status(200)
                        .type("text/html; charset=UTF-8")
                        .entity(html)
                        .build();
            }

            // Use raw code if it differs (i.e. '+' was mangled to space)
            String codeToUse = (rawCode != null && !rawCode.equals(decodedCode)) ? rawCode : decodedCode;

            // VNeID-specific: decrypt the authorization code if encrypt_key is present
            if (rawEncryptKey != null && !rawEncryptKey.isBlank() && codeToUse != null && !codeToUse.isBlank()) {
                codeToUse = decryptAuthorizationCode(codeToUse, rawEncryptKey);
                logger.infof("VNeID: decrypted code (length=%d)=%s", codeToUse.length(), codeToUse);
            }

            logger.infof("VNeID: using code (length=%d)=%s", codeToUse == null ? 0 : codeToUse.length(), codeToUse);

            // Delegate to parent with the corrected code
            return super.authResponse(state, codeToUse, error, errorDescription);
        }

        private String escapeHtml(String s) {
            if (s == null) return "";
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
        }

        private String escapeAttr(String s) {
            if (s == null) return "";
            return s.replace("'", "&apos;").replace("\"", "&quot;").replace("\n", "&#10;");
        }

        /** Reads a parameter value from the raw (un-decoded) query string to preserve '+' signs. */
        private String extractRawParam(String paramName) {
            try {
                String rawQuery = session.getContext().getUri().getRequestUri().getRawQuery();
                if (rawQuery == null) return null;
                for (String pair : rawQuery.split("&")) {
                    int eq = pair.indexOf('=');
                    if (eq < 0) continue;
                    String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8.name());
                    if (paramName.equals(key)) {
                        // Decode value with '+' preserved as literal '+' (not space)
                        // Replace '+' with %2B before decoding so URLDecoder leaves it as '+'
                        String rawValue = pair.substring(eq + 1).replace("+", "%2B");
                        return URLDecoder.decode(rawValue, StandardCharsets.UTF_8.name());
                    }
                }
            } catch (UnsupportedEncodingException e) {
                logger.warnf("VNeID: extractRawParam failed: %s", e.getMessage());
            }
            return null;
        }

        @Override
        public SimpleHttp generateTokenRequest(String authorizationCode) {
            // Build redirect_uri — must exactly match what was registered with VNeID
            String callbackUrl = session.getContext().getUri().getBaseUri().toString();
            if (callbackUrl.endsWith("/")) {
                callbackUrl = callbackUrl.substring(0, callbackUrl.length() - 1);
            }
            String redirectUri = callbackUrl
                    + "/realms/" + realm.getName()
                    + "/broker/" + getConfig().getAlias()
                    + "/endpoint";

            // Retrieve encrypt_key from session (set in authResponse)
            String encryptKey = (String) session.getAttribute("vneid_encrypt_key");

            logger.infof("VNeID: generateTokenRequest: tokenUrl=%s, client_id=%s, redirect_uri=%s, has_secret=%b, has_encrypt_key=%b, code (length=%d)=%s",
                    getConfig().getTokenUrl(), getConfig().getClientId(), redirectUri,
                    getConfig().getClientSecret() != null && !getConfig().getClientSecret().isBlank(),
                    encryptKey != null && !encryptKey.isBlank(),
                    authorizationCode.length(), authorizationCode);

            // Log full request body for debugging
            String secret = getConfig().getClientSecret();
            logger.infof("VNeID: token request params: grant_type=authorization_code, code=%s, client_id=%s, redirect_uri=%s, client_secret=%s, encrypt_key=%s",
                    authorizationCode.substring(0, Math.min(30, authorizationCode.length())) + "...",
                    getConfig().getClientId(),
                    redirectUri,
                    secret != null ? secret.substring(0, Math.min(8, secret.length())) + "..." : "null",
                    encryptKey != null ? encryptKey.substring(0, Math.min(30, encryptKey.length())) + "..." : "null");

            SimpleHttp req = SimpleHttp.doPost(getConfig().getTokenUrl(), session)
                    .param("grant_type", "authorization_code")
                    .param("code", authorizationCode)
                    .param("client_id", getConfig().getClientId())
                    .param("redirect_uri", redirectUri);

            if (secret != null && !secret.isBlank()) {
                req.param("client_secret", secret);
            }

            // VNeID-specific: send encrypt_key if present
            if (encryptKey != null && !encryptKey.isBlank()) {
                req.param("encrypt_key", encryptKey);
            }

            return req;
        }
    }
}
