package com.fptaptech.catalog.auth;

import com.fptaptech.catalog.user.AppUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final Duration refreshTtl;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               @Value("${app.jwt.refresh-ttl:7d}") Duration refreshTtl) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTtl = refreshTtl;
    }

    public record RotatedTokenResult(String newRawToken, AppUser user) {}

    @Transactional
    public String createRefreshToken(AppUser user, String ipAddress, String userAgent) {
        String familyId = UUID.randomUUID().toString();
        return generateAndPersistToken(user, familyId, ipAddress, userAgent);
    }

    @Transactional(noRollbackFor = RefreshTokenReusedException.class)
    public RotatedTokenResult rotateRefreshToken(String rawToken, String ipAddress, String userAgent) {
        String incomingHash = hashToken(rawToken);
        RefreshToken foundToken = refreshTokenRepository.findByTokenHash(incomingHash)
                .orElse(null);

        // Constant-time check verification
        if (foundToken == null || !MessageDigest.isEqual(foundToken.getTokenHash().getBytes(StandardCharsets.UTF_8), incomingHash.getBytes(StandardCharsets.UTF_8))) {
            throw new InvalidRefreshTokenException("Refresh token không hợp lệ hoặc không tồn tại");
        }

        Instant now = Instant.now();

        // Check if token was already revoked / used -> REUSE DETECTION TRIGGERED!
        if (foundToken.getRevokedAt() != null) {
            String familyId = foundToken.getFamilyId();
            refreshTokenRepository.revokeAllByFamilyId(familyId, now);
            log.warn("CẢNH BÁO AN NINH: Phát hiện tái sử dụng Refresh Token! Family ID: {}, User ID: {}",
                    familyId, foundToken.getUser().getId());
            throw new RefreshTokenReusedException("Phát hiện tái sử dụng Refresh Token! Toàn bộ chuỗi phiên đã bị thu hồi.");
        }

        // Check if token expired
        if (now.isAfter(foundToken.getExpiresAt())) {
            throw new InvalidRefreshTokenException("Refresh token đã hết hạn");
        }

        // Mark current token as revoked/used
        foundToken.setRevokedAt(now);
        refreshTokenRepository.save(foundToken);

        // Issue new token in the same family
        AppUser user = foundToken.getUser();
        String newRawToken = generateAndPersistToken(user, foundToken.getFamilyId(), ipAddress, userAgent);
        return new RotatedTokenResult(newRawToken, user);
    }

    @Transactional
    public void revokeToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return;
        String hash = hashToken(rawToken);
        refreshTokenRepository.findByTokenHash(hash).ifPresent(token -> {
            token.setRevokedAt(Instant.now());
            refreshTokenRepository.save(token);
        });
    }

    @Transactional
    public void revokeAllByUserId(Long userId) {
        refreshTokenRepository.revokeAllByUserId(userId, Instant.now());
    }

    private String generateAndPersistToken(AppUser user, String familyId, String ipAddress, String userAgent) {
        String rawToken = generateRawToken();
        String hash = hashToken(rawToken);
        Instant now = Instant.now();

        RefreshToken token = RefreshToken.builder()
                .user(user)
                .tokenHash(hash)
                .familyId(familyId)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .createdAt(now)
                .expiresAt(now.plus(refreshTtl))
                .build();

        refreshTokenRepository.save(token);
        return rawToken;
    }

    private String generateRawToken() {
        byte[] bytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Thuật toán SHA-256 không được hỗ trợ", e);
        }
    }
}
