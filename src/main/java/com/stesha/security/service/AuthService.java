package com.stesha.security.service;

import com.stesha.security.model.*;
import com.stesha.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserRepository repository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthResponse register(RegisterRequest request) {
    var user = User.builder()
        .fName(request.getFName())
        .lName(request.getLName())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(Role.USER)
        .build();

    repository.save(user);
    var jwtToken = jwtService.generateToken(user);
    return AuthResponse.builder()
        .token(jwtToken)
        .build();
  }

  public AuthResponse authenticate(AuthRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(), request.getPassword()
        )
    ); //user is authenticated

    var user = repository.findByEmail(request.getEmail())
        .orElseThrow(); // todo add try/catch

    var jwtToken = jwtService.generateToken(user);
    return AuthResponse.builder()
        .token(jwtToken)
        .build();
  }
}
