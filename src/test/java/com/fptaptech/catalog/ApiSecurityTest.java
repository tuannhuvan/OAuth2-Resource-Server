package com.fptaptech.catalog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fptaptech.catalog.auth.LoginRequest;
import com.fptaptech.catalog.config.RateLimiterService;
import com.fptaptech.catalog.product.ProductRequest;
import com.fptaptech.catalog.product.ProductService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItems;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
public class ApiSecurityTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProductService productService;

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

    @Test
    @DisplayName("1. Đăng nhập đúng trả về Token chứa roles [ROLE_USER, ROLE_ADMIN]")
    void validCredentialsReturnSignedToken() throws Exception {
        LoginRequest loginRequest = new LoginRequest("admin", "DefaultAdminPass2026");

        MvcResult result = mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        JsonNode json = objectMapper.readTree(responseBody);
        String accessToken = json.get("accessToken").asText();

        // Verify with /api/auth/me
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.roles", hasItems("ROLE_USER", "ROLE_ADMIN")));
    }

    @Test
    @DisplayName("2. Đăng nhập sai mật khẩu trả về 401 ProblemDetail")
    void wrongPasswordReturnsProblemDetail() throws Exception {
        LoginRequest loginRequest = new LoginRequest("admin", "WrongPassword123");

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.title").value("Authentication failed"))
                .andExpect(jsonPath("$.detail").value("Sai username hoặc mật khẩu"))
                .andExpect(jsonPath("$.type").value("https://example.com/errors/invalid-credentials"));
    }

    @Test
    @DisplayName("3. Truy cập GET /api/v1/products thành công không cần Token (200 OK)")
    void anyoneCanReadProducts() throws Exception {
        mockMvc.perform(get("/api/v1/products"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.pagination").exists());
    }

    @Test
    @DisplayName("4. Gửi POST /api/v1/products không có Token trả về 401 kèm WWW-Authenticate challenge")
    void writeWithoutTokenReturns401WithBearerChallenge() throws Exception {
        ProductRequest product = new ProductRequest("Sản phẩm cấm", "Mô tả", new BigDecimal("100000.00"));

        mockMvc.perform(post("/api/v1/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(product)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("Bearer")));
    }

    @Test
    @DisplayName("5. Token có ROLE_USER gửi POST /api/v1/products bị chặn bởi 403 Forbidden")
    void userRoleCannotCreateProduct() throws Exception {
        LoginRequest userLogin = new LoginRequest("user", "UserPass2026");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userLogin)))
                .andExpect(status().isOk())
                .andReturn();

        String token = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("accessToken").asText();

        ProductRequest product = new ProductRequest("Hack Product", "Mô tả", new BigDecimal("500000.00"));
        mockMvc.perform(post("/api/v1/products")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(product)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("6. Token có ROLE_ADMIN gửi POST /api/v1/products tạo mới thành công (201 Created)")
    void adminRoleCanCreateProduct() throws Exception {
        LoginRequest adminLogin = new LoginRequest("admin", "DefaultAdminPass2026");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(adminLogin)))
                .andExpect(status().isOk())
                .andReturn();

        String token = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("accessToken").asText();

        ProductRequest product = new ProductRequest("Sản phẩm của Admin", "Mô tả chuẩn", new BigDecimal("990000.00"));
        mockMvc.perform(post("/api/v1/products")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(product)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.id").isNumber())
                .andExpect(jsonPath("$.data.name").value("Sản phẩm của Admin"));
    }

    @Test
    @DisplayName("7. Token biến dạng / sai chữ ký bị từ chối với 401")
    void malformedTokenIsRejected() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.invalidpayload.invalidsignature"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("error=\"invalid_token\"")));
    }

    @Test
    @DisplayName("8. Phòng thủ 2 lớp: Gọi trực tiếp ProductService.create() mà không có vai trò ADMIN bị ném AccessDeniedException")
    @WithMockUser(username = "user", roles = {"USER"})
    void serviceRejectsNonAdminEvenWithoutHttp() {
        ProductRequest product = new ProductRequest("Lậu", "Mô tả", new BigDecimal("100.00"));

        assertThatThrownBy(() -> productService.create(product))
                .isInstanceOf(AccessDeniedException.class);
    }
}
