package com.example.SocialJwtApplication.Service;

import com.example.SocialJwtApplication.DTOs.JwtResponse;
import com.example.SocialJwtApplication.DTOs.LoginRequest;
import com.example.SocialJwtApplication.DTOs.SignupRequest;
import com.example.SocialJwtApplication.Model.RefreshToken;
import com.example.SocialJwtApplication.Model.User;
import com.example.SocialJwtApplication.Repository.RefreshTokenRepository;
import com.example.SocialJwtApplication.Repository.UserRepository;
import com.example.SocialJwtApplication.SecurityJWTUtils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    public String registerUser(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new RuntimeException("Error: Username is already taken!");
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new RuntimeException("Error: Email is already in use!");
        }

        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setBio(signUpRequest.getBio());
        user.setProfileImageUrl(signUpRequest.getProfileImageUrl());
        Set<String> strRoles = signUpRequest.getRoles();
        Set<String> roles = new HashSet<>();
        if (strRoles == null || strRoles.isEmpty()) {
            roles.add("ROLE_USER");
        } else {
            for (String r : strRoles) {
                if (r.equalsIgnoreCase("admin")) roles.add("ROLE_ADMIN");
                else roles.add("ROLE_USER");
            }
        }
        user.setRoles(roles);

        userRepository.save(user);
        return "User registered successfully!";
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsernameOrEmail())
                .orElseGet(() -> userRepository.findByEmail(loginRequest.getUsernameOrEmail()).orElse(null));
        if (user == null) throw new RuntimeException("Error: User not found");
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new RuntimeException("Error: Invalid credentials");
        }

        String accessToken = jwtUtils.generateAccessToken(user);

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setToken(jwtUtils.generateRefreshToken());

        refreshToken.setUser(user);

        refreshToken.setExpiryDate(Instant.now().plusMillis(Long.parseLong(System.getProperty("app.jwtRefreshExpirationMs", String.valueOf(2592000000L)))));

        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtUtils == null ? 0L : jwtUtils.generateRefreshToken() == null ? 0L : 0L));

        refreshToken = saveRefreshTokenForUser(user);
        return new JwtResponse(accessToken, refreshToken.getToken(), user.getId(), user.getUsername(), user.getEmail(), new ArrayList<>(user.getRoles()));
    }

    @Autowired
    private RefreshTokenService refreshTokenService;

    private RefreshToken saveRefreshTokenForUser(User user) {
        return refreshTokenService.createRefreshToken(user.getId());
    }
}
