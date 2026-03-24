package com.scb.keycloak;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.*;
import org.keycloak.models.UserSessionModel.SessionPersistenceState;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.common.util.Time;
import org.keycloak.util.JsonSerialization;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class OpaqueResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;
    private static final SecureRandom SR = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    public OpaqueResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() { return this; }

    public String getNewToken() {
        byte[] bytes = new byte[32];
        SR.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }

    @POST
    @Path("token")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response issueToken(@FormParam("client_id") String clientId,
                               @FormParam("client_secret") String clientSecret) {

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null || !client.isEnabled() || clientSecret == null || !clientSecret.equals(client.getSecret())) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(Map.of("error", "unauthorized")).build();
        }

        UserModel serviceAccount = session.users().getServiceAccount(client);
        if (serviceAccount == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(Map.of("error", "service_account_disabled")).build();
        }

        session.getContext().setClient(client);

        String tokenType = client.getAttribute("token.type");

        UserSessionModel userSession = session.sessions().createUserSession(
                null, realm, serviceAccount, serviceAccount.getUsername(),
                session.getContext().getConnection().getRemoteAddr(),
                "opaque-auth", false, null, null,
                SessionPersistenceState.PERSISTENT
        );
        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client, userSession);
        ClientSessionContext ctx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, session);

        if ("opaque".equalsIgnoreCase(tokenType)) {
            String uuid = getNewToken();
            userSession.setNote("opaque_handle", uuid);
            return Response.ok(new OpaqueTokenResponse(uuid, (long) realm.getAccessTokenLifespan())).build();
        } else {
            TokenManager tokenManager = new TokenManager();
            AccessToken token = tokenManager.createClientAccessToken(session, realm, client, serviceAccount, userSession, ctx);
            String encodedJwt = session.tokens().encode(token);
            return Response.ok(new OpaqueTokenResponse(encodedJwt, (long) realm.getAccessTokenLifespan())).build();
        }
    }

    @POST
    @Path("introspect")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response introspect(@FormParam("token") String token, @FormParam("client_id") String clientId) {
        if (token == null || clientId == null) return Response.ok(Map.of("active", false)).build();

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) return Response.ok(Map.of("active", false)).build();

        session.getContext().setClient(client);

        // --- BRANCH 1: JWT INTROSPECTION ---
        if (token.contains(".")) {
            try {
                // FIXED VERIFIER: Using session.tokens().decode() is the safest way in modern Keycloak
                AccessToken jwt = session.tokens().decode(token, AccessToken.class);

                if (jwt == null) {
                    return Response.ok(Map.of("active", false, "error", "invalid_token")).build();
                }

                @SuppressWarnings("unchecked")
                Map<String, Object> response = JsonSerialization.mapper.convertValue(jwt, Map.class);
                response.put("active", true);
                return Response.ok(response).build();
            } catch (Exception e) {
                e.printStackTrace();
                return Response.ok(Map.of("active", false, "error", "verification_failed")).build();
            }
        }

        // --- BRANCH 2: OPAQUE INTROSPECTION ---
        UserSessionModel userSession = session.sessions().getUserSessionsStream(realm, client)
                .filter(s -> token.equals(s.getNote("opaque_handle")))
                .findFirst()
                .orElse(null);

        if (userSession == null) return Response.ok(Map.of("active", false)).build();

        if (Time.currentTime() > (userSession.getStarted() + realm.getAccessTokenLifespan())) {
            return Response.ok(Map.of("active", false)).build();
        }

        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, session);

        TokenManager tokenManager = new TokenManager();
        AccessToken jwtPayload = tokenManager.createClientAccessToken(session, realm, client, userSession.getUser(), userSession, clientSessionCtx);

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("active", true);
        try {
            responseMap.putAll(JsonSerialization.mapper.convertValue(jwtPayload, Map.class));
        } catch (Exception e) {
            e.printStackTrace();
            responseMap.put("sub", userSession.getUser().getId());
        }

        return Response.ok(responseMap).build();
    }

    @Override public void close() {}
}