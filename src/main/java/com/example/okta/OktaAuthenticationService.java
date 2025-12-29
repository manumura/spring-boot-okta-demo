package com.example.okta;

import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Set;

@Slf4j
@Service
public class OktaAuthenticationService {

    private final IDXAuthenticationWrapper idxAuthenticationWrapper;

    public OktaAuthenticationService(
            @Value("${okta.domain}") String oktaDomain,
            @Value("${okta.client-id}") String clientId,
            @Value("${okta.redirect-uri}") String redirectUri,
            @Value("${okta.scopes:openid email profile offline_access}") Set<String> scopes) {

        this.idxAuthenticationWrapper = new IDXAuthenticationWrapper(
            "https://" + oktaDomain,
            clientId,
            null,
            scopes,
            redirectUri
        );
    }

    // https://developer.okta.com/docs/guides/oie-embedded-sdk-use-case-basic-sign-in/java/main/
    // https://developer.okta.com/docs/guides/set-up-org/main/#set-up-your-okta-org-for-a-password-factor-only-use-case
    public TokenResponse authenticate(String email, String password) {
        try {
            AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin();

            AuthenticationResponse authResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions(email, password.toCharArray()),
                beginResponse.getProceedContext()
            );

            log.info("Authentication response status: {} - errors: {} ", authResponse.getAuthenticationStatus(), authResponse.getErrors());
            validateAuthenticationResponse(authResponse);
            logTokenDetails(authResponse.getTokenResponse());

            return authResponse.getTokenResponse();

        } catch (Exception e) {
            log.error("Authentication failed for user: {}", email, e);
            throw new AuthenticationException("Authentication failed: " + e.getMessage(), e);
        }
    }

    private void validateAuthenticationResponse(AuthenticationResponse response) {
        if (response == null) {
            throw new AuthenticationException("Authentication response is null");
        }

        if (response.getAuthenticationStatus() != AuthenticationStatus.SUCCESS) {
            log.error("Authentication failed with status: {}", response.getAuthenticationStatus());
            throw new AuthenticationException(
                "Authentication failed with status: " + response.getAuthenticationStatus()
            );
        }
    }

    private void logTokenDetails(TokenResponse tokenResponse) {
        if (tokenResponse != null) {
            log.info("Access Token: {}", tokenResponse.getAccessToken());
            log.info("Token Type: {}", tokenResponse.getTokenType());
            log.info("Expires In: {}", tokenResponse.getExpiresIn());
            log.info("Scope: {}", tokenResponse.getScope());
            log.info("Refresh Token: {}", tokenResponse.getRefreshToken());
            log.info("ID Token: {}", tokenResponse.getIdToken());
        }
    }
}
