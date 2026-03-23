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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class OpaqueResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;

    public OpaqueResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() { return this; }

    @POST
    @Path("token")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response issueOpaqueToken(@FormParam("client_id") String clientId,
                                     @FormParam("client_secret") String clientSecret) {

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null || !client.isEnabled()) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(Map.of("error", "invalid_client")).build();
        }
        if (clientSecret == null || !clientSecret.equals(client.getSecret())) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(Map.of("error", "invalid_client_secret")).build();
        }

        UserModel serviceAccount = session.users().getServiceAccount(client);
        if (serviceAccount == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(Map.of("error", "service_account_disabled")).build();
        }

        UserSessionModel userSession = session.sessions().createUserSession(
                null, realm, serviceAccount, serviceAccount.getUsername(),
                session.getContext().getConnection().getRemoteAddr(),
                "opaque-auth", false, null, null,
                SessionPersistenceState.PERSISTENT
        );

        session.sessions().createClientSession(realm, client, userSession);

        String uuid = UUID.randomUUID().toString();
        userSession.setNote("opaque_handle", uuid);

        int lifespan = realm.getAccessTokenLifespan();
        return Response.ok(new OpaqueTokenResponse(uuid, lifespan)).build();
    }

    @POST
    @Path("introspect")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response introspect(@FormParam("token") String token, @FormParam("client_id") String clientId) {
        if (token == null || token.isEmpty() || clientId == null) {
            return Response.ok(Map.of("active", false)).build();
        }

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) return Response.ok(Map.of("active", false)).build();

        UserSessionModel userSession = session.sessions().getUserSessionsStream(realm, client)
                .filter(s -> token.equals(s.getNote("opaque_handle")))
                .findFirst()
                .orElse(null);

        if (userSession == null) return Response.ok(Map.of("active", false)).build();

        int expirationTime = userSession.getStarted() + realm.getAccessTokenLifespan();
        if (Time.currentTime() > expirationTime) {
            return Response.ok(Map.of("active", false, "reason", "expired")).build();
        }

        // --- CRITICAL FIX START ---
        // Manually set the client in the context to prevent the NPE in TokenManager
        session.getContext().setClient(client);
        // --- CRITICAL FIX END ---

        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, session);

        TokenManager tokenManager = new TokenManager();
        AccessToken jwtPayload = tokenManager.createClientAccessToken(session, realm, client, userSession.getUser(), userSession, clientSessionCtx);

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("active", true);

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> fullClaims = JsonSerialization.mapper.convertValue(jwtPayload, Map.class);
            responseMap.putAll(fullClaims);
        } catch (Exception e) {
            responseMap.put("sub", userSession.getUser().getId());
            responseMap.put("username", userSession.getUser().getUsername());
        }

        return Response.ok(responseMap).build();
    }

    @Override public void close() {}
}