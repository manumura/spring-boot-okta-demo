package com.example.okta;

import com.okta.authn.sdk.AuthenticationStateHandlerAdapter;
import com.okta.authn.sdk.resource.AuthenticationResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class CustomAuthenticationStateHandler extends AuthenticationStateHandlerAdapter {

    @Override
    public void handleUnknown(AuthenticationResponse unknownResponse) {
        // redirect to "/error"
        log.error("Unknown authentication response: {}", unknownResponse);
    }

    @Override
    public void handleSuccess(AuthenticationResponse successResponse) {

        // a user is ONLY considered authenticated if a sessionToken exists
        if (StringUtils.isNotBlank(successResponse.getSessionToken())) {
            log.info("Authentication successful: {}", successResponse);
            String relayState = successResponse.getRelayState();
            String dest = relayState != null ? relayState : "/";
            // redirect to dest
        }
        // other state transition successful
    }

    @Override
    public void handlePasswordExpired(AuthenticationResponse passwordExpired) {
        // redirect to "/login/change-password"
        log.info("Password expired: {}", passwordExpired);
    }

    // Other implemented states here
}
