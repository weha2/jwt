package com.weha.jwt.controllers;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@PreAuthorize("hasAuthority('ADMIN')")
@RestController
@RequestMapping("/api/admin")
@Tag(name = "Admin", description = "APIs for admin.")
public class AdminController {

    @GetMapping("")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello, from admin");
    }
}
