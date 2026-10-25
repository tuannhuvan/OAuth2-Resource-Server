# ĐẶC TẢ YÊU CẦU PHẦN MỀM (SRS) & BÀI TOÁN NGHIỆP VỤ
## Tên hệ thống: Bảo Vệ REST API Bằng JWT Với Spring Security 7 (OAuth2 Resource Server)
**Tác giả:** Senior Business Analyst (BA)  
**Phiên bản:** 2.0.0  
**Ngày lập:** 23/10/2026  
**Nền tảng mục tiêu:** Java 25 / Spring Boot 4.1.1 / Spring Security 7.1.x / MySQL 8.4 LTS  

---

## 1. TỔNG QUAN BÀI TOÁN & PHẠM VI HỆ THỐNG

### 1.1 Mục tiêu Hệ thống
Xây dựng giải pháp an ninh và phân quyền cho hệ thống **Catalog REST API** sử dụng chuẩn **JSON Web Token (JWT)** tích hợp với **Spring Security 7 (OAuth2 Resource Server)** [1]. Hệ thống hoạt động theo mô hình **Stateless Architecture**, trong đó:
- Client thực hiện trao đổi thông tin định danh (`username`/`password`) để lấy **Access Token** có thời gian sống ngắn (15 phút), được ký số bằng thuật toán bất đối xứng **RSA (RS256)** [1, 2, 11].
- Mọi truy vấn tiếp theo đến Nguồn tài nguyên (Resource APIs) phải đính kèm Token trong HTTP Header (`Authorization: Bearer <JWT>`) [1]. Server thực hiện kiểm tra chữ ký và claims trong Token mà **không chạm Database** ở lớp xác thực tài nguyên [1, 3].
- Mở rộng cơ chế quản lý phiên đăng nhập an toàn tích hợp **Refresh Token Rotation**, **Phát hiện tái sử dụng Refresh Token (Reuse Detection)**, **Đăng xuất đơn / Đăng xuất tất cả thiết bị (SLO)**, **Xoay khóa ký (JWKS Key Rotation)** và **Giới hạn tần suất (Rate Limiting 429)** [38, 39, 41, 42].

### 1.2 Bối cảnh Hệ thống & Công nghệ
- **Mô hình kiến trúc:** Stateless RESTful API / OAuth2 Resource Server [1, 2].
- **JDK:** Java 25 (LTS) - Sử dụng Virtual Threads & Record Patterns [5, 49].
- **Framework:** Spring Boot 4.1.1, Spring Security 7.1.x (`spring-boot-starter-security-oauth2-resource-server`, `spring-boot-starter-security-oauth2-jose`) [5, 8].
- **Database & Migration:** MySQL 8.4 LTS quản lý qua Docker Compose, sử dụng Flyway (`flyway-mysql`) cho Schema Versioning (`ddl-auto: validate`) [5, 6, 9].
- **Tài liệu hóa & Testing:** OpenApi 3.1.1 (Swagger UI với `persist-authorization`), JUnit 5, `spring-security-test`, H2 In-Memory DB [5, 10, 12, 32].

---

## 2. PHÂN TÍCH THÀNH PHẦN & TÁC NHÂN (ACTORS & SUBSYSTEMS)

### 2.1 Tác nhân (Actors)
1. **Anonymous Consumer (Khách hàng vãng lai / Public Client):** Xem danh mục sản phẩm (`GET /api/v1/products/**`), truy cập tài liệu Swagger UI (`/swagger-ui.html`), đổi thông tin lấy Token (`POST /api/auth/token`) [3, 15].
2. **Authenticated User (ROLE_USER):** Người dùng đã đăng nhập thành công, xem thông tin cá nhân/token (`GET /api/auth/me`), thực hiện Refresh Token (`POST /api/auth/refresh`), Đăng xuất (`POST /api/auth/logout`) [3, 21, 38, 39].
3. **Administrator (ROLE_ADMIN):** Quản trị viên hệ thống có toàn quyền thêm, sửa, xóa sản phẩm (`POST`, `PUT`, `DELETE /api/v1/products/**`), đăng xuất mọi thiết bị (`POST /api/auth/logout-all`), đổi mật khẩu người dùng (`POST /api/auth/change-password`) [4, 24, 39].

### 2.2 Sơ đồ Cấu trúc Gói (Package Structure) [7]
```text
com.fptaptech.catalog/
├── CatalogApplication.java
├── config/
│   ├── OpenApiConfig.java          # Cấu hình SecurityScheme (bearerAuth)
│   └── SecurityConfig.java         # SecurityFilterChain Stateless, JwtDecoder, JwtEncoder, Beans
├── auth/
│   ├── AuthController.java         # Endpoints: /token, /refresh, /logout, /logout-all, /me
│   ├── LoginRequest.java          # DTO Record (username, password)
│   ├── RefreshRequest.java        # DTO Record (refreshToken)
│   ├── TokenResponse.java         # DTO Record (accessToken, refreshToken, tokenType, expiresIn)
│   ├── TokenService.java          # Cấp phát JWT Access Token (RS256, claims)
│   ├── RefreshTokenService.java   # Quản lý Refresh Token & Reuse Detection
│   └── AdminSeeder.java           # Khởi tạo tài khoản ADMIN mặc định lúc Startup
├── common/
│   └── GlobalExceptionHandler.java # Bắt lỗi AuthenticationException, AccessDeniedException, RFC 7807
├── product/
│   ├── ProductController.java     # REST API Sản phẩm
│   ├── ProductService.java        # Nghiệp vụ Sản phẩm với phòng thủ @PreAuthorize("hasRole('ADMIN')")
│   └── Product.java               # Entity
└── user/
    ├── AppUser.java / Role.java   # Entities
    ├── UserRepository.java        # JPA Repository
    └── DatabaseUserDetailsService.java # Nạp thông tin người dùng & vai trò từ DB
```

---

## 3. YÊU CẦU CHỨC NĂNG TỔNG THỂ (FUNCTIONAL REQUIREMENTS)

| Mã Yêu Cầu | Tên Chức Năng | Mô Tả Chi Tiết & Tiêu Chí Nghiệm Thu | Lớp Phân Quyền |
| :--- | :--- | :--- | :--- |
| **FR-01** | Đăng nhập lấy Token | Khách gửi `POST /api/auth/token` với JSON `{username, password}`. Trả về `accessToken` (JWT 15 phút), `refreshToken` (opaque token 7 ngày), `expiresIn: 900` [18, 38]. Nhập sai trả 401 ProblemDetail [22]. | Public (`permitAll`) [15] |
| **FR-02** | Xem thông tin Token | Gửi `GET /api/auth/me` kèm Header `Authorization: Bearer <JWT>`. Trả về JSON chứa `username`, `roles`, `expiresAt` [21]. | Authenticated (`ROLE_USER`/`ADMIN`) [15] |
| **FR-03** | Truy cập Sản phẩm | `GET /api/v1/products/**` cho phép đọc thông tin sản phẩm công khai mà không cần Token [3, 15]. | Public (`permitAll`) [15] |
| **FR-04** | Quản trị Sản phẩm | `POST`, `PUT`, `DELETE /api/v1/products/**` yêu cầu Token có vai trò `ROLE_ADMIN` hoặc Scope `SCOPE_product:write` [4, 24, 42]. | Admin (`ROLE_ADMIN`) [15, 24] |
| **FR-05** | Refresh Token Rotation | Gửi `POST /api/auth/refresh` với `refreshToken` cũ. Hệ thống kiểm tra SHA-256 hash trong DB, đánh dấu token cũ đã dùng và trả về cặp `accessToken` + `refreshToken` mới [38]. | Public / Valid Refresh Token [38] |
| **FR-06** | Reuse Detection | Nếu gửi lại một `refreshToken` đã bị đánh dấu ngắt/dùng trước đó, hệ thống lập tức thu hồi **TOÀN BỘ** chuỗi token thuộc cùng `family_id`, trả lỗi `401 REFRESH_TOKEN_REUSED` và ghi log WARN [38]. | System Security Event [38] |
| **FR-07** | Đăng xuất (Logout) | Gửi `POST /api/auth/logout`. Thu hồi `refreshToken` hiện tại và đưa `jti` của `accessToken` vào danh sách thu hồi cho đến khi hết hạn [39]. | Authenticated [39] |
| **FR-08** | Đăng xuất tất cả | Gửi `POST /api/auth/logout-all`. Thu hồi mọi `refreshToken` của user và tăng `token_version` trong bảng `users` để vô hiệu hóa toàn bộ `accessToken` đã cấp [39]. | Authenticated [39] |
| **FR-09** | Tự động Seed Admin | Khi `app.seed-admin.enabled=true`, ứng dụng tự khởi tạo tài khoản `admin` với password mã hóa qua `PasswordEncoder` nếu chưa tồn tại [25, 26]. | System Startup [25] |

---

## 4. YÊU CẦU PHI CHỨC NĂNG (NON-FUNCTIONAL REQUIREMENTS)

| Mã NFR | Tiêu Chi | Yêu Cầu Chi Tiết |
| :--- | :--- | :--- |
| **NFR-01** | **Stateless Verification** | Quá trình kiểm tra Access Token tại `JwtDecoder` sử dụng Khóa Công Khai (Public Key RS256). **Không được phép truy vấn Database** ở mỗi request đọc tài nguyên [1, 3, 11]. |
| **NFR-02** | **Hiệu lực Thu hồi (Latency Window)** | Yêu cầu thu hồi token (Logout / Logout-all / Change Password) có hiệu lực tối đa trong vòng **5 giây**. Được phép cache trạng thái thu hồi nhưng không query DB quá 1 lần/request [40]. |
| **NFR-03** | **Bảo mật Thông tin Log** | Tuyệt đối **KHÔNG** ghi chuỗi `accessToken`, `refreshToken`, hoặc `password` ra log ở bất kỳ log level nào (DEBUG, INFO, ERROR) [40]. |
| **NFR-04** | **Constant-time Comparison** | Việc so sánh chuỗi băm SHA-256 của Refresh Token phải thực hiện bằng thuật toán so sánh thời gian hằng (`MessageDigest.isEqual`) để chống tấn công Timing Attack [41]. |
| **NFR-05** | **Xoay khóa Ký (Key Rotation)** | Hệ thống hỗ trợ tối thiểu 2 khóa RSA cùng lúc phân biệt bằng `kid`. Mọi token mới ký bằng khóa `active`. Xuất bản danh sách public key tại `GET /.well-known/jwks.json` [41]. |
| **NFR-06** | **Rate Limiting** | Endpoint `/api/auth/token` và `/api/auth/refresh` giới hạn tối đa **10 requests / phút / IP**. Vượt quá ngưỡng trả về HTTP `429 Too Many Requests` kèm Header `Retry-After` [42]. |

---

## 5. CƠ SỞ DỮ LIỆU & SCHEMA MIGRATION (FLYWAY)

### 5.1 Bảng `users`, `roles`, `users_roles` (V1__init_schema.sql) [6, 39]
```sql
CREATE TABLE users (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    token_version BIGINT       NOT NULL DEFAULT 0,
    created_at    DATETIME(6)  NOT NULL,
    updated_at    DATETIME(6)  NOT NULL
);

CREATE TABLE roles (
    id   BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(30) NOT NULL UNIQUE
);

CREATE TABLE users_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);
```

### 5.2 Bảng `products` (V2__products.sql) [6]
```sql
CREATE TABLE products (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(120)   NOT NULL,
    description VARCHAR(500),
    price       DECIMAL(12, 2) NOT NULL,
    created_at  DATETIME(6),
    updated_at  DATETIME(6)
);
```

### 5.3 Bảng `refresh_tokens` & `revoked_tokens` (V3__refresh_tokens.sql) [38, 39]
```sql
CREATE TABLE refresh_tokens (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT       NOT NULL,
    token_hash    VARCHAR(64)  NOT NULL UNIQUE,
    family_id     VARCHAR(36)  NOT NULL,
    ip_address    VARCHAR(45),
    user_agent    VARCHAR(255),
    expires_at    DATETIME(6)  NOT NULL,
    revoked_at    DATETIME(6)  NULL,
    created_at    DATETIME(6)  NOT NULL,
    CONSTRAINT fk_rt_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE revoked_tokens (
    jti        VARCHAR(36) PRIMARY KEY,
    expires_at DATETIME(6) NOT NULL
);
```

---

## 6. MÔ TẢ ĐẦU RA VÀ QUY CHUẨN MÃ LỖI (RFC 7807 PROBLEM DETAILS)

### 6.1 Cấu trúc Thành công (200 OK / 201 Created) [18, 23]
`POST /api/auth/token` Response:
```json
{
  "accessToken": "eyJraWQiOiJjYXRhbG9nLWtleS0xIiwiaWQiOiJSUzI1NiJ9...",
  "refreshToken": "7f8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

### 6.2 Cấu trúc Mã Lỗi CHUẨN (application/problem+json) [12, 22, 28, 42]
1. **Lỗi Xác thực Đăng nhập (401 Unauthorized):** [22]
```json
{
  "type": "https://example.com/errors/invalid-credentials",
  "title": "Authentication failed",
  "status": 401,
  "detail": "Sai username hoặc mật khẩu",
  "instance": "/api/auth/token",
  "timestamp": "2026-10-23T10:15:30Z"
}
```
2. **Lỗi Token Hết hạn / Chữ ký Sai (401 Unauthorized):** [29, 31]
   HTTP Response Header: `WWW-Authenticate: Bearer error="invalid_token", error_description="Jwt expired at 2026-10-23T10:00:00Z"`
3. **Lỗi Thiếu Quyền Hạn (403 Forbidden):** [25, 28]
```json
{
  "type": "https://example.com/errors/access-denied",
  "title": "Access Denied",
  "status": 403,
  "detail": "Tài khoản không có quyền thực hiện thao tác này (Yêu cầu ROLE_ADMIN)",
  "instance": "/api/v1/products",
  "timestamp": "2026-10-23T10:16:00Z"
}
```
4. **Lỗi Vượt Giới Hạn Tần Suất (429 Too Many Requests):** [42]
   HTTP Response Headers: `Retry-After: 60`
```json
{
  "type": "https://example.com/errors/rate-limit-exceeded",
  "title": "Too Many Requests",
  "status": 429,
  "detail": "Bạn đã vượt quá giới hạn 10 lượt yêu cầu/phút. Vui lòng thử lại sau 60 giây.",
  "instance": "/api/auth/token",
  "timestamp": "2026-10-23T10:17:00Z"
}
```

---

## 7. YÊU CẦU KIỂM THỬ TỰ ĐỘNG (AUTOMATED TEST SUITE REQUIREMENT) [33-37, 43, 44]

Bộ test tự động (`ApiSecurityTest.java`) phải kiểm tra đầy đủ các kịch bản nghiệm thu sau:
1. `validCredentialsReturnSignedToken()`: Đăng nhập đúng trả về Token chứa claim `roles: ["ROLE_USER", "ROLE_ADMIN"]` [35].
2. `wrongPasswordReturnsProblemDetail()`: Đăng nhập sai mật khẩu trả về 401 dạng `ProblemDetail` [35].
3. `anyoneCanReadProducts()`: Truy cập `GET /api/v1/products` thành công không cần Token (200 OK) [35].
4. `writeWithoutTokenReturns401WithBearerChallenge()`: Gửi `POST /api/v1/products` không có Token trả về 401 kèm header `WWW-Authenticate` [35].
5. `userRoleCannotCreateProduct()`: Token có `ROLE_USER` gửi `POST /api/v1/products` bị chặn bởi 403 Forbidden [35].
6. `adminRoleCanCreateProduct()`: Token có `ROLE_ADMIN` gửi `POST /api/v1/products` tạo mới thành công (201 Created) [36].
7. `malformedTokenIsRejected()`: Token biến dạng/sai chữ ký bị từ chối với 401 [36].
8. `serviceRejectsNonAdminEvenWithoutHttp()`: Kiểm tra phòng thủ 2 lớp, gọi trực tiếp `ProductService.create()` mà không có vai trò ADMIN bị ném `AccessDeniedException` trực tiếp tại Java Service [36, 37].
9. `refreshTokenRotationAndReuseDetection()`: Test xoay vòng refresh token thành công và phát hiện gửi lại token cũ làm thu hồi toàn bộ `family_id` [43, 44].
