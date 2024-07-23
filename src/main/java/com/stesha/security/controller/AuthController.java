package com.stesha.security.controller;

import com.stesha.security.model.AuthRequest;
import com.stesha.security.model.AuthResponse;
import com.stesha.security.model.RegisterRequest;
import com.stesha.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService service;

  @PostMapping("/register")
  public ResponseEntity<AuthResponse> register(
      @RequestBody RegisterRequest request) {
    return ResponseEntity.ok(service.register(request));

  }

  @PostMapping("/authenticate")
  public ResponseEntity<AuthResponse> register(
      @RequestBody AuthRequest request) {
    return ResponseEntity.ok(service.authenticate(request));
  }
}
