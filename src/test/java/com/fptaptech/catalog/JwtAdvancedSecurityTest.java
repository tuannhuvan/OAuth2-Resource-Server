package com.fptaptech.catalog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fptaptech.catalog.auth.ChangePasswordRequest;
import com.fptaptech.catalog.auth.LoginRequest;
import com.fptaptech.catalog.auth.RefreshRequest;
import com.fptaptech.catalog.auth.TokenRevocationService;
import com.fptaptech.catalog.config.JwkKeyManager;
import com.fptaptech.catalog.config.RateLimiterService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
public class JwtAdvancedSecurityTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwkKeyManager jwkKeyManager;

    @Autowired
    private TokenRevocationService tokenRevocationService;

    @Autowired
    private RateLimiterService rateLimiterService;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
        rateLimiterService.reset();
    }

    private record TokenPair(String accessToken, String refreshToken) {}

    private TokenPair login(String username, String password) throws Exception {
        LoginRequest req = new LoginRequest(username, password);
        MvcResult res = mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode json = objectMapper.readTree(res.getResponse().getContentAsString());
        return new TokenPair(json.get("accessToken").asText(), json.get("refreshToken").asText());
    }

    @Test
    @DisplayName("REQ-1: Xoay vòng refresh token thành công (Trả về cặp Access Token + Refresh Token mới)")
    void testSuccessfulRefreshTokenRotation() throws Exception {
        TokenPair initial = login("admin", "DefaultAdminPass2026");

        RefreshRequest refreshReq = new RefreshRequest(initial.refreshToken());
        MvcResult res = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        JsonNode json = objectMapper.readTree(res.getResponse().getContentAsString());
        String newAccessToken = json.get("accessToken").asText();
        String newRefreshToken = json.get("refreshToken").asText();

        // Refresh token mới phải khác refresh token cũ
        assertThat(newRefreshToken).isNotEqualTo(initial.refreshToken());

        // Access token mới truy cập tài nguyên hợp lệ
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"));
    }

    @Test
    @DisplayName("REQ-2: Dùng lại refresh token cũ làm cả chuỗi bị thu hồi (Reuse Detection)")
    void testReusingOldRefreshTokenRevokesEntireFamilyChain() throws Exception {
        TokenPair initial = login("admin", "DefaultAdminPass2026");
        String oldRefreshToken = initial.refreshToken();

        // Lần 1: Xoay vòng hợp lệ
        RefreshRequest refreshReq1 = new RefreshRequest(oldRefreshToken);
        MvcResult res1 = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq1)))
                .andExpect(status().isOk())
                .andReturn();

        String newRefreshToken = objectMapper.readTree(res1.getResponse().getContentAsString()).get("refreshToken").asText();

        // Lần 2: Kẻ tấn công hoặc client gửi lại oldRefreshToken đã dùng
        RefreshRequest reuseReq = new RefreshRequest(oldRefreshToken);
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(reuseReq)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail", containsString("Phát hiện tái sử dụng Refresh Token")));

        // Lần 3: Thử dùng newRefreshToken (vốn đang active) -> CẢ CHUỖI ĐÃ BỊ THU HỒI
        RefreshRequest familyReq = new RefreshRequest(newRefreshToken);
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(familyReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("REQ-3: Access token bị từ chối sau logout (Single Logout - JTI Blacklist)")
    void testAccessTokenRejectedAfterLogout() throws Exception {
        TokenPair pair = login("admin", "DefaultAdminPass2026");

        // Trước khi logout: Access token hợp lệ
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isOk());

        // Thực hiện logout
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + pair.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RefreshRequest(pair.refreshToken()))))
                .andExpect(status().isOk());

        // Sau khi logout: Access token bị từ chối ngay lập tức
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("invalid_token")));
    }

    @Test
    @DisplayName("REQ-4: Mọi token bị từ chối sau logout-all (Logout All / SLO)")
    void testAllTokensRejectedAfterLogoutAll() throws Exception {
        TokenPair pair = login("admin", "DefaultAdminPass2026");

        // Trước logout-all: token hợp lệ
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isOk());

        // Gọi POST /api/auth/logout-all
        mockMvc.perform(post("/api/auth/logout-all")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isOk());

        // Sau logout-all: access token bị từ chối (token_version không còn khớp)
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isUnauthorized());

        // Refresh token cũng bị thu hồi
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RefreshRequest(pair.refreshToken()))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("REQ-5: Mọi token bị từ chối sau khi đổi mật khẩu")
    void testAllTokensRejectedAfterPasswordChange() throws Exception {
        TokenPair pair = login("user", "UserPass2026");

        // Đổi mật khẩu
        ChangePasswordRequest changeReq = new ChangePasswordRequest("UserPass2026", "NewUserPass2026!");
        mockMvc.perform(post("/api/auth/change-password")
                        .header("Authorization", "Bearer " + pair.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeReq)))
                .andExpect(status().isOk());

        // Token cũ bị từ chối ngay
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isUnauthorized());

        // Refresh token cũ cũng bị thu hồi
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RefreshRequest(pair.refreshToken()))))
                .andExpect(status().isUnauthorized());

        // Đăng nhập lại bằng mật khẩu mới thành công
        TokenPair newPair = login("user", "NewUserPass2026!");
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + newPair.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user"));
    }

    @Test
    @DisplayName("REQ-6: Token ký bằng khóa cũ vẫn được chấp nhận (JWKS Key Rotation)")
    void testTokenSignedWithOldKeyStillAccepted() throws Exception {
        RSAKey oldKey = jwkKeyManager.getKey("catalog-key-1");
        assertThat(oldKey).isNotNull();

        long currentVer = tokenRevocationService.getUserTokenVersion("admin");

        JWSSigner signer = new RSASSASigner(oldKey.toRSAPrivateKey());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("catalog-api")
                .subject("admin")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                .jwtID(UUID.randomUUID().toString())
                .claim("roles", List.of("ROLE_ADMIN", "ROLE_USER"))
                .claim("ver", currentVer)
                .build();

        SignedJWT oldToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("catalog-key-1").build(),
                claims
        );
        oldToken.sign(signer);

        String oldTokenString = oldToken.serialize();

        // Gửi token ký bằng catalog-key-1 đến Resource Server -> Được chấp nhận (200 OK)
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + oldTokenString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    @DisplayName("REQ-7: Token có kid lạ bị từ chối (401 Unauthorized)")
    void testTokenWithUnknownKidRejected() throws Exception {
        // Sinh cặp khóa ngẫu nhiên hoàn toàn không có trong JWKS
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair unknownPair = kpg.generateKeyPair();

        JWSSigner signer = new RSASSASigner(unknownPair.getPrivate());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("catalog-api")
                .subject("admin")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                .jwtID(UUID.randomUUID().toString())
                .claim("roles", List.of("ROLE_ADMIN", "ROLE_USER"))
                .claim("ver", 0L)
                .build();

        SignedJWT unknownKidJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown-alien-kid-999").build(),
                claims
        );
        unknownKidJwt.sign(signer);

        String alienToken = unknownKidJwt.serialize();

        // Gửi token có kid lạ -> Bị từ chối với 401
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + alienToken))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("error=\"invalid_token\"")));
    }

    @Test
    @DisplayName("REQ-8: Request thứ 11 trong 1 phút nhận HTTP 429 Too Many Requests kèm Retry-After: 60")
    void testEleventhRequestWithinOneMinuteReceives429() throws Exception {
        LoginRequest req = new LoginRequest("admin", "DefaultAdminPass2026");
        String content = objectMapper.writeValueAsString(req);

        // 10 requests đầu tiên được chấp nhận
        for (int i = 1; i <= 10; i++) {
            mockMvc.perform(post("/api/auth/token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(content))
                    .andExpect(status().isOk());
        }

        // Request thứ 11 trong cùng 1 phút nhận 429 Too Many Requests
        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(content))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.title").value("Too Many Requests"))
                .andExpect(jsonPath("$.type").value("https://example.com/errors/rate-limit-exceeded"))
                .andExpect(jsonPath("$.detail", containsString("vượt quá giới hạn 10 lượt yêu cầu/phút")));
    }
}
