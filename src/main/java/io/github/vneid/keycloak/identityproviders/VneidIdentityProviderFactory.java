package io.github.vneid.keycloak.identityproviders;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory for VNeID Identity Provider.
 * Registers custom config properties for:
 * <ul>
 *   <li>RSA private key (for decrypting encrypted responses)</li>
 *   <li>Configurable userinfo claim names</li>
 *   <li>Auto-account-linking toggle</li>
 * </ul>
 */
public class VneidIdentityProviderFactory extends OIDCIdentityProviderFactory {

    public static final String PROVIDER_ID = "vneid";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        // RSA Private Key for decryption
        ProviderConfigProperty privateKeyProp = new ProviderConfigProperty();
        privateKeyProp.setName(VneidIdentityProvider.PRIVATE_KEY_CONFIG);
        privateKeyProp.setLabel("RSA Private Key (PEM)");
        privateKeyProp.setHelpText("PKCS8 PEM private key for decrypting VNeID encrypted responses (authorization code, token, userinfo)");
        privateKeyProp.setType(ProviderConfigProperty.STRING_TYPE);
        privateKeyProp.setSecret(true);
        configProperties.add(privateKeyProp);

        // User ID claim name
        ProviderConfigProperty userIdClaimProp = new ProviderConfigProperty();
        userIdClaimProp.setName(VneidIdentityProvider.USER_ID_CLAIM_CONFIG);
        userIdClaimProp.setLabel("User ID Claim");
        userIdClaimProp.setHelpText("Claim name in userinfo response used as user identifier (default: citizenPid)");
        userIdClaimProp.setType(ProviderConfigProperty.STRING_TYPE);
        userIdClaimProp.setDefaultValue(VneidIdentityProvider.DEFAULT_USER_ID_CLAIM);
        configProperties.add(userIdClaimProp);

        // Full name claim name
        ProviderConfigProperty nameClaimProp = new ProviderConfigProperty();
        nameClaimProp.setName(VneidIdentityProvider.NAME_CLAIM_CONFIG);
        nameClaimProp.setLabel("Full Name Claim");
        nameClaimProp.setHelpText("Claim name in userinfo response used as full name (default: fullName)");
        nameClaimProp.setType(ProviderConfigProperty.STRING_TYPE);
        nameClaimProp.setDefaultValue(VneidIdentityProvider.DEFAULT_NAME_CLAIM);
        configProperties.add(nameClaimProp);

        // Birth date claim name
        ProviderConfigProperty birthDateClaimProp = new ProviderConfigProperty();
        birthDateClaimProp.setName(VneidIdentityProvider.BIRTH_DATE_CLAIM_CONFIG);
        birthDateClaimProp.setLabel("Birth Date Claim");
        birthDateClaimProp.setHelpText("Claim name in userinfo response used as birth date (default: birthDate)");
        birthDateClaimProp.setType(ProviderConfigProperty.STRING_TYPE);
        birthDateClaimProp.setDefaultValue(VneidIdentityProvider.DEFAULT_BIRTH_DATE_CLAIM);
        configProperties.add(birthDateClaimProp);

        // Debug mode
        ProviderConfigProperty debugProp = new ProviderConfigProperty();
        debugProp.setName(VneidIdentityProvider.DEBUG_SKIP_TOKEN_CONFIG);
        debugProp.setLabel("Debug Mode");
        debugProp.setHelpText("When enabled, skip token exchange and show debug page with curl commands. Disable in production.");
        debugProp.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        debugProp.setDefaultValue("false");
        configProperties.add(debugProp);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "VNeID";
    }

    @Override
    public VneidIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new VneidIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }

    @Override
    public OIDCIdentityProviderConfig createConfig() {
        return new OIDCIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
