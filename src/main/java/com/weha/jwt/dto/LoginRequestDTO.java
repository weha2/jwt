package com.weha.jwt.dto;

public record LoginRequestDTO(
        String username,
        String password
) {
}
