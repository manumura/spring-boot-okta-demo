package com.example.okta;

import com.okta.idx.sdk.api.response.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final OktaAuthenticationService oktaAuthenticationService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {
        TokenResponse tokenResponse = oktaAuthenticationService.authenticate(
            loginRequest.email(),
            loginRequest.password()
        );
        return ResponseEntity.ok(tokenResponse);
    }

    @GetMapping("/login/callback")
    public ResponseEntity<Void> loginCallback(@RequestParam String code,
                                               @RequestParam(required = false) String state) {
        log.info("Login callback received - code: {}, state: {}", code, state);
        // Process OAuth callback
        return ResponseEntity.ok().build();
    }
}
