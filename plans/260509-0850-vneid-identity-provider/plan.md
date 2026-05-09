# VNeID Identity Provider for Keycloak 26.0

**Status:** in_progress  
**Priority:** High  
**Created:** 2026-05-09

---

## Overview

Custom Keycloak Identity Provider for VNeID integration, extending the OIDC provider with encrypted response handling.

## Key Requirements

1. **Maven project** targeting Keycloak 26.0
2. **VneidIdentityProvider** extending `OidcIdentityProvider`
3. **VneidIdentityProviderFactory** implementing `IdentityProviderFactory`
4. **Form-urlencoded token request** (not JSON)
5. **Encrypted response decryption:**
   - RSA/ECB/PKCS1Padding for key decryption
   - AES/CBC/PKCS5Padding for data decryption (IV = first 16 bytes)
6. **Configuration fields:** clientId, clientSecret, authorizationUrl, tokenUrl, userInfoUrl, logoutUrl, privateKey (PEM)
7. **Override:** `getAccessToken`, `parseResponse`

## Architecture

```
pbpl-keycloak-extensions/
├── pom.xml
├── src/main/java/com/pbpl/keycloak/
│   ├── identityproviders/
│   │   ├── VneidIdentityProvider.java
│   │   └── VneidIdentityProviderFactory.java
│   └── crypto/
│       └── VneidResponseDecryptor.java
├── src/main/resources/
│   └── META-INF/
│       └── services/
│           └── org.keycloak.broker.provider.IdentityProviderFactory
└── src/test/java/com/pbpl/keycloak/
    └── identityproviders/
        └── VneidIdentityProviderTest.java
```

## Implementation Phases

### Phase 1: Project Setup
- Create Maven pom.xml with Keycloak 26.0 dependencies
- Set up directory structure

### Phase 2: Core Provider Implementation
- VneidIdentityProvider extending OidcIdentityProvider
- Override getAccessToken for form-urlencoded token request
- Override parseResponse for encrypted response handling
- VneidIdentityProviderFactory with configuration

### Phase 3: Crypto Module
- RSA private key PEM parsing
- AES decryption with IV extraction
- VneidResponseDecryptor utility class

### Phase 4: Service Registration
- META-INF/services registration
- Provider configuration properties

### Phase 5: Testing
- Unit tests for decryption logic
- Integration test scaffolding

## Success Criteria

- [ ] Maven compiles successfully
- [ ] Provider registers in Keycloak admin console
- [ ] Token request uses form-urlencoded format
- [ ] Encrypted responses are decrypted correctly
- [ ] All unit tests pass

## Dependencies

- keycloak-core:26.0.0
- keycloak-server-spi:26.0.0
- keycloak-server-spi-private:26.0.0
- keycloak-services:26.0.0

## Files to Create

1. `pom.xml`
2. `src/main/java/com/pbpl/keycloak/identityproviders/VneidIdentityProvider.java`
3. `src/main/java/com/pbpl/keycloak/identityproviders/VneidIdentityProviderFactory.java`
4. `src/main/java/com/pbpl/keycloak/crypto/VneidResponseDecryptor.java`
5. `src/main/resources/META-INF/services/org.keycloak.broker.provider.IdentityProviderFactory`
6. `src/test/java/com/pbpl/keycloak/identityproviders/VneidIdentityProviderTest.java`
