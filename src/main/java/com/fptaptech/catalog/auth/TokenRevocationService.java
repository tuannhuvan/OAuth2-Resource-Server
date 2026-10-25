package com.fptaptech.catalog.auth;

import com.fptaptech.catalog.user.AppUser;
import com.fptaptech.catalog.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenRevocationService {

    private static final Logger log = LoggerFactory.getLogger(TokenRevocationService.class);

    private final RevokedTokenRepository revokedTokenRepository;
    private final UserRepository userRepository;

    // Cache of revoked JTIs with their expiration timestamps
    private final Map<String, Instant> revokedJtiCache = new ConcurrentHashMap<>();

    // Cache of username to tokenVersion
    private final Map<String, Long> userTokenVersionCache = new ConcurrentHashMap<>();

    public TokenRevocationService(RevokedTokenRepository revokedTokenRepository,
                                  UserRepository userRepository) {
        this.revokedTokenRepository = revokedTokenRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public void revokeJti(String jti, Instant expiresAt) {
        if (jti == null) return;
        revokedJtiCache.put(jti, expiresAt != null ? expiresAt : Instant.now().plusSeconds(900));
        RevokedToken rt = RevokedToken.builder()
                .jti(jti)
                .expiresAt(expiresAt != null ? expiresAt : Instant.now().plusSeconds(900))
                .build();
        revokedTokenRepository.save(rt);
        log.info("Access token JTI thu hồi thành công: {}", jti);
    }

    public boolean isJtiRevoked(String jti) {
        if (jti == null) return false;
        Instant exp = revokedJtiCache.get(jti);
        if (exp != null) {
            if (Instant.now().isAfter(exp)) {
                revokedJtiCache.remove(jti);
                return false;
            }
            return true;
        }
        // Fallback to DB if not in memory
        boolean inDb = revokedTokenRepository.existsByJti(jti);
        if (inDb) {
            revokedJtiCache.put(jti, Instant.now().plusSeconds(900));
        }
        return inDb;
    }

    @Transactional
    public long incrementUserTokenVersion(String username) {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy user: " + username));
        long newVersion = user.getTokenVersion() + 1;
        user.setTokenVersion(newVersion);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        userTokenVersionCache.put(username, newVersion);
        log.info("Đã tăng token_version cho user [{}] lên {}", username, newVersion);
        return newVersion;
    }

    public long getUserTokenVersion(String username) {
        Long cached = userTokenVersionCache.get(username);
        if (cached != null) {
            return cached;
        }
        return userRepository.findByUsername(username)
                .map(user -> {
                    userTokenVersionCache.put(username, user.getTokenVersion());
                    return user.getTokenVersion();
                })
                .orElse(0L);
    }

    public boolean isTokenVersionValid(String username, Long tokenVersion) {
        if (username == null) return false;
        long currentVersion = getUserTokenVersion(username);
        long tokenVer = (tokenVersion != null) ? tokenVersion : 0L;
        return tokenVer >= currentVersion;
    }
}
