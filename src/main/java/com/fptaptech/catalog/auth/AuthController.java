package com.fptaptech.catalog.auth;

import com.fptaptech.catalog.config.JwkKeyManager;
import com.fptaptech.catalog.user.AppUser;
import com.fptaptech.catalog.user.Role;
import com.fptaptech.catalog.user.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@Tag(name = "Authentication & Sessions", description = "Quản lý cấp phát JWT, xoay vòng Refresh Token, Logout & Đổi mật khẩu")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final TokenRevocationService tokenRevocationService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwkKeyManager jwkKeyManager;

    public AuthController(AuthenticationManager authenticationManager,
                          TokenService tokenService,
                          RefreshTokenService refreshTokenService,
                          TokenRevocationService tokenRevocationService,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwkKeyManager jwkKeyManager) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
        this.tokenRevocationService = tokenRevocationService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwkKeyManager = jwkKeyManager;
    }

    @PostMapping("/api/auth/token")
    @Operation(summary = "Đăng nhập lấy Token (Public)", description = "Cấp Access Token (JWT 15m) và Refresh Token (7d)")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        AppUser user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new BadCredentialsException("Sai username hoặc mật khẩu"));

        String ip = extractIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        String refreshToken = refreshTokenService.createRefreshToken(user, ip, userAgent);

        TokenResponse response = tokenService.issue(auth, refreshToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/api/auth/refresh")
    @Operation(summary = "Xoay vòng Refresh Token (Public)", description = "Đổi Refresh Token cũ lấy cặp Access Token + Refresh Token mới (Phát hiện dùng lại)")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest httpRequest) {
        String ip = extractIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        RefreshTokenService.RotatedTokenResult result = refreshTokenService.rotateRefreshToken(request.refreshToken(), ip, userAgent);
        AppUser user = result.user();

        List<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .toList();

        TokenResponse response = tokenService.issueToken(user.getUsername(), roles, user.getTokenVersion(), result.newRawToken());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/auth/me")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Xem thông tin phiên người dùng hiện tại", description = "Yêu cầu JWT Bearer Token")
    public ResponseEntity<UserSummaryResponse> getMe(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Instant exp = null;
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            exp = jwt.getExpiresAt();
        }

        return ResponseEntity.ok(new UserSummaryResponse(username, roles, exp));
    }

    @PostMapping("/api/auth/logout")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Đăng xuất thiết bị hiện tại (Single Logout)", description = "Thu hồi Access Token JTI và Refresh Token")
    public ResponseEntity<Map<String, String>> logout(Authentication authentication,
                                                      @RequestBody(required = false) RefreshRequest refreshRequest) {
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            String jti = jwt.getId();
            Instant exp = jwt.getExpiresAt();
            tokenRevocationService.revokeJti(jti, exp);
        }

        if (refreshRequest != null && refreshRequest.refreshToken() != null) {
            refreshTokenService.revokeToken(refreshRequest.refreshToken());
        }

        return ResponseEntity.ok(Map.of("message", "Đăng xuất thành công. Token đã bị vô hiệu hóa."));
    }

    @PostMapping("/api/auth/logout-all")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Đăng xuất tất cả thiết bị (Logout All / SLO)", description = "Tăng token_version và thu hồi toàn bộ Refresh Token của tài khoản")
    public ResponseEntity<Map<String, String>> logoutAll(Authentication authentication) {
        String username = authentication.getName();
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        tokenRevocationService.incrementUserTokenVersion(username);
        refreshTokenService.revokeAllByUserId(user.getId());

        return ResponseEntity.ok(Map.of("message", "Đã đăng xuất toàn bộ thiết bị. Mọi token trước đó đã bị thu hồi."));
    }

    @PostMapping("/api/auth/change-password")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Đổi mật khẩu người dùng", description = "Đổi mật khẩu và tự động thu hồi toàn bộ phiên đăng nhập cũ")
    public ResponseEntity<Map<String, String>> changePassword(Authentication authentication,
                                                              @Valid @RequestBody ChangePasswordRequest request) {
        String username = authentication.getName();
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (!passwordEncoder.matches(request.oldPassword(), user.getPasswordHash())) {
            throw new BadCredentialsException("Mật khẩu cũ không chính xác");
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        // Invalidate all tokens
        tokenRevocationService.incrementUserTokenVersion(username);
        refreshTokenService.revokeAllByUserId(user.getId());

        return ResponseEntity.ok(Map.of("message", "Đổi mật khẩu thành công. Mọi token đã cấp trước đó bị vô hiệu hóa."));
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "Xuất bản danh sách khóa công khai (JWKS)", description = "Cung cấp Public Keys phục vụ xác minh chữ ký bất đối xứng (Key Rotation)")
    public Map<String, Object> getJwks() {
        return jwkKeyManager.getPublicJwkSet().toJSONObject();
    }

    private String extractIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
