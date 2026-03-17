package com.scb.keycloak;

import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ClientAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class X509AuthenticatorFactory implements ClientAuthenticatorFactory {

    public static final String PROVIDER_ID = "imperva-mtls-authenticator";

    // Client authenticators are stateless, so we can use a single instance
    private static final X509Authenticator SINGLETON = new X509Authenticator();

    // FIX: The parameterless create() method required by newer ClientAuthenticatorFactory interfaces
    @Override
    public ClientAuthenticator create() {
        return SINGLETON;
    }

    // Standard ProviderFactory create method
    @Override
    public ClientAuthenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Imperva mTLS Base64 Validator";
    }

    @Override
    public String getReferenceCategory() {
        return "client-credentials";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates the Base64 x-mtls header against the pinned_client_cert attribute.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if ("openid-connect".equals(loginProtocol)) {
            return Collections.singleton(PROVIDER_ID);
        }
        return Collections.emptySet();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        return Collections.emptyMap();
    }

    @Override
    public boolean supportsSecret() {
        return false;
    }

    // ConfiguredPerClientProvider interface method (sometimes required depending on the exact minor version)
    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return Collections.emptyList();
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}