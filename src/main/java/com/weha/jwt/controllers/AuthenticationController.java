package com.weha.jwt.controllers;

import com.weha.jwt.dto.LoginRequestDTO;
import com.weha.jwt.services.AuthenticationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/authenticate")
@Tag(name = "Authentication", description = "APIs for managing authenticate")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping("refresh-token")
    public ResponseEntity<String> refreshToken() {
        return ResponseEntity.ok(authenticationService.refreshToken());
    }

    @PostMapping("login")
    public ResponseEntity<String> login(@RequestBody LoginRequestDTO request) {
        return ResponseEntity.ok(authenticationService.login(request));
    }
}
