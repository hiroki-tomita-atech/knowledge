package org.support.project.web.entity;

public class TokenEntity {
    private String accessToken;
    private int expiresIn;
    private String scope;
    private String tokenType;
    private String idToken;

    public TokenEntity(String accessToken, int expiresIn, String scope, String tokenType, String idToken) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.scope = scope;
        this.tokenType = tokenType;
        this.idToken = idToken;
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    public String getScope() {
        return this.scope;
    }

    public int getExpiresIn() {
        return this.expiresIn;
    }
}
