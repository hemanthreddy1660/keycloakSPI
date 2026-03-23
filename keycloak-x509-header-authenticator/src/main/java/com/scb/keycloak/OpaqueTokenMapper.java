package com.scb.keycloak;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.representations.AccessToken;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.ArrayList;
import java.util.List;

public class OpaqueTokenMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {
    public static final String PROVIDER_ID = "strict-opaque-mapper";

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        String handle = userSession.getNote("opaque_handle");
        if (handle != null) token.getOtherClaims().put("opaque_handle", handle);
        return token;
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Opaque Reference Mapper"; }
    @Override public String getDisplayCategory() { return TOKEN_MAPPER_CATEGORY; }
    @Override public String getHelpText() { return "Adds the opaque handle to internal tokens."; }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<>();
    }
}