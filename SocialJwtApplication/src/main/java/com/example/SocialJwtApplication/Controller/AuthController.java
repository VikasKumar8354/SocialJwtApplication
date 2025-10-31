package com.example.SocialJwtApplication.Controller;

import com.example.SocialJwtApplication.DTOs.LoginRequest;
import com.example.SocialJwtApplication.DTOs.SignupRequest;
import com.example.SocialJwtApplication.DTOs.TokenRefreshRequest;
import com.example.SocialJwtApplication.DTOs.TokenRefreshResponse;
import com.example.SocialJwtApplication.Model.RefreshToken;
import com.example.SocialJwtApplication.Repository.UserRepository;
import com.example.SocialJwtApplication.SecurityJWTUtils.JwtUtils;
import com.example.SocialJwtApplication.Service.AuthService;
import com.example.SocialJwtApplication.Service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthService authService;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserRepository userRepository;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        try {
            String msg = authService.registerUser(signUpRequest);
            return ResponseEntity.ok(msg);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            var jwtResponse = authService.authenticateUser(loginRequest);
            return ResponseEntity.ok(jwtResponse);
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateAccessToken(user);

                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseGet(() -> ResponseEntity
                        .badRequest()
                        .body(new TokenRefreshResponse("","Refresh token is not in database!")));

    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshToken -> {
                    refreshTokenService.verifyExpiration(refreshToken);
                    refreshTokenService.deleteByUserId(refreshToken.getUser().getId());
                    return ResponseEntity.ok("User logged out successfully!");
                })
                .orElseGet(() -> ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid or expired token"));
    }

    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<?> deleteTokensByUserId(@PathVariable Long userId) {
        try {
            int deletedCount = refreshTokenService.deleteByUserId(userId);
            if (deletedCount > 0) {
                return ResponseEntity.ok("Deleted " + deletedCount + " refresh token(s) for user ID: " + userId);
            } else {
                return ResponseEntity.ok("No refresh tokens found for user ID: " + userId);
            }
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
