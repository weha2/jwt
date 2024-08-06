package com.weha.jwt.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.weha.jwt.dto.LoginRequestDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class AuthenticationService {

    @Value("${app.token.secret}")
    private String secret;

    @Value("${app.token.issuer}")
    private String issuer;

    @Value("${app.token.expire}")
    private Long expire;

    public String login(LoginRequestDTO request) {
        boolean isValid = isUser(request) || isAdmin(request);
        if (isValid) {
            boolean isAdmin = isAdmin(request);
            return createToken(
                    isAdmin ? ADMIN.principal : USER.principal,
                    request.username(),
                    isAdmin ? "ADMIN" : "USER"
            );
        }
        return "Invalid username or password";
    }

    public String refreshToken() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        String principal = (String) authentication.getPrincipal();
        if (principal != null) {
            boolean isAdmin = principal.equals(ADMIN.principal);
            return createToken(
                    isAdmin ? ADMIN.principal : USER.principal,
                    isAdmin ? ADMIN.username : USER.username,
                    isAdmin ? "ADMIN" : "USER"
            );
        }
        return "Invalid bearer";
    }

    private String createToken(String principal, String username, String role) {
        Date now = new Date();
        Date expire = new Date(now.getTime() + this.expire * 1000);
        return JWT.create()
                .withIssuer(issuer)
                .withClaim("username", username)
                .withClaim("principal", principal)
                .withClaim("role", role)
                .withExpiresAt(expire)
                .sign(algorithm());
    }

    public DecodedJWT decodedJWT(String token) {
        JWTVerifier verifier = JWT.require(algorithm())
                .withIssuer(issuer)
                .build();
        return verifier.verify(token);
    }

    private boolean isUser(LoginRequestDTO request) {
        return request.username().equals(USER.username) && request.password().equals(USER.password);
    }

    private boolean isAdmin(LoginRequestDTO request) {
        return request.username().equals(ADMIN.username) && request.password().equals(ADMIN.password);
    }

    private Algorithm algorithm() {
        return Algorithm.HMAC256(secret);
    }

    private interface USER {
        String principal = "1";
        String username = "weha";
        String password = "1234";
    }

    private interface ADMIN {
        String principal = "2";
        String username = "admin";
        String password = "1234";
    }
}
