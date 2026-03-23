package com.scb.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OpaqueTokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("expires_in")
    private long expiresIn;
    @JsonProperty("token_type")
    private String tokenType = "Bearer";

    public OpaqueTokenResponse() {}
    public OpaqueTokenResponse(String accessToken, long expiresIn) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
    }
    public String getAccessToken() { return accessToken; }
    public long getExpiresIn() { return expiresIn; }
    public String getTokenType() { return tokenType; }
}