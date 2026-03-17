package com.scb.keycloak;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;

public class X509Authenticator implements ClientAuthenticator {

    private static final String MTLS_HEADER = "x-mtls";
    private static final String STORED_CERT_ATTR = "pinned_client_cert";

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        System.out.println("\n>>> [SPI DEBUG] --- Starting Imperva mTLS Authentication ---");

        // 1. Extract Client ID
        MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();
        String clientId = formParams.getFirst(OAuth2Constants.CLIENT_ID);
        System.out.println(">>> [SPI DEBUG] Request Client ID: " + clientId);

        if (clientId == null) {
            System.out.println(">>> [SPI DEBUG] FAILED: Client ID is missing.");
            context.attempted();
            return;
        }

        // 2. Fetch Client
        RealmModel realm = context.getRealm();
        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null) {
            System.out.println(">>> [SPI DEBUG] FAILED: Client '" + clientId + "' not found.");
            context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
            return;
        }

        // 3. Extract Certificate from Header (with safety for unit tests)
        Map<String, List<String>> headers = null;
        if (context.getHttpRequest().getHttpHeaders() != null) {
            headers = context.getHttpRequest().getHttpHeaders().getRequestHeaders();
        }

        System.out.println(">>> [SPI DEBUG] Incoming Headers:");
        if (headers != null) {
            headers.forEach((k, v) -> System.out.println("    " + k + ": " + v));
        } else {
            System.out.println("    [No headers found - likely a Mock/Test environment]");
        }

        String headerB64Cert = context.getHttpRequest().getHttpHeaders().getHeaderString(MTLS_HEADER);
        if (headerB64Cert == null) {
            headerB64Cert = context.getHttpRequest().getHttpHeaders().getHeaderString("X-MTLS");
        }

        // 4. Fetch Stored Certificate
        String storedPemCert = client.getAttribute(STORED_CERT_ATTR);

        System.out.println(">>> [SPI DEBUG] Header Raw: [" + headerB64Cert + "]");
        System.out.println(">>> [SPI DEBUG] Stored Raw: [" + storedPemCert + "]");

        if (headerB64Cert == null || storedPemCert == null) {
            System.out.println(">>> [SPI DEBUG] FAILED: Header or Attribute is NULL.");
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
                    Response.status(Response.Status.UNAUTHORIZED).entity("Missing MTLS config").build());
            return;
        }

        // 5. Clean and Compare
        String cleanHeader = cleanBase64(headerB64Cert);
        String cleanStored = cleanBase64(storedPemCert);

        System.out.println(">>> [SPI DEBUG] Cleaned Header: " + cleanHeader);
        System.out.println(">>> [SPI DEBUG] Cleaned Stored: " + cleanStored);

        if (cleanHeader.equals(cleanStored)) {
            System.out.println(">>> [SPI DEBUG] SUCCESS: Match! Authenticating.");
            context.setClient(client);
            context.success();
        } else {
            System.out.println(">>> [SPI DEBUG] FAILED: Certificate mismatch.");
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
                    Response.status(Response.Status.UNAUTHORIZED).entity("MTLS mismatch").build());
        }
    }

    private String cleanBase64(String input) {
        if (input == null) return "";
        return input.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("-----BEGIN CERT---", "")
                .replaceAll("-----END CERT---", "")
                .replaceAll("\\s+", "")
                .replaceAll("%20", "")
                .replaceAll("%0A", "")
                .replaceAll("\"", "")
                .trim();
    }

    @Override
    public void close() {}
}