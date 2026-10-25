# HƯỚNG DẪN KIẾN TRÚC HỆ THỐNG & CHUẨN THIẾT KẾ REST API
## Hệ thống Xác thực Tập trung SSO/SLO & Thiết kế RESTful Standard
**Tài liệu tham chiếu:** Build APIs You Won't Hate (Phil Sturgeon) & JWT SSO/SLO Architecture Guide  
**Mục tiêu:** Định hướng cho Đội ngũ Phát triển & AI Agent triển khai hệ thống REST API chuẩn Enterprise.

---

## 1. NGUYÊN TẮC THIẾT KẾ RESTFUL API (TỪ BUILD APIS YOU WON'T HATE)

### 1.1 Nguyên tắc Định danh Nguồn tài nguyên (Nouns vs Verbs) [96, 110, 111]
- **Sử dụng Danh từ Số nhiều (Plural Nouns):** Sử dụng danh từ số nhiều nhất quán cho tất cả các URI để đại diện cho tập hợp tài nguyên (Collection) [109, 110].
  - `/api/v1/products`, `/api/v1/products/123`, `/api/auth/tokens`
- **Tách biệt Hành động bằng HTTP Verbs:** [106, 111]
  - `GET`: Đọc tài nguyên (Idempotent & Safe) [103].
  - `POST`: Tạo mới tài nguyên hoặc thực thi tác vụ xử lý [106].
  - `PUT`: Thay thế toàn bộ tài nguyên (Idempotent) [106].
  - `PATCH`: Cập nhật một phần tài nguyên [112].
  - `DELETE`: Xóa tài nguyên (Idempotent) [105].

### 1.2 Định dạng Dữ liệu Đầu ra & Namespace [143-145]
Tất cả các phản hồi JSON phải tuân thủ cấu trúc đồng nhất có Namespace để dễ dàng mở rộng Metadata (như Pagination, Links, Meta):
- **Phản hồi Đơn lẻ (Single Resource):** [143]
```json
{
  "data": {
    "id": 1,
    "name": "Bàn phím cơ Wireless",
    "price": 1250000.00,
    "created_at": "2026-10-23T10:00:00Z"
  }
}
```
- **Phản hồi Tập hợp (Collection & Pagination):** [144, 301]
```json
{
  "data": [
    { "id": 1, "name": "Bàn phím cơ Wireless", "price": 1250000.00 }
  ],
  "pagination": {
    "total": 100,
    "per_page": 10,
    "current_page": 1,
    "total_pages": 10
  }
}
```

### 1.3 Chuẩn Mã Lỗi HTTP & RFC 7807 Problem Details [147-149, 162]
- Không bao giờ trả về HTTP `200 OK` đi kèm một body báo lỗi [163]. Lỗi tầng HTTP phải đúng mã trạng thái HTTP:
  - `400 Bad Request`: Dữ liệu đầu vào sai định dạng/validation [149].
  - `401 Unauthorized`: Chưa xác thực hoặc Token hết hạn/sai chữ ký [149].
  - `403 Forbidden`: Đã xác thực nhưng không đủ quyền truy cập [149].
  - `404 Not Found`: Đường dẫn hoặc ID tài nguyên không tồn tại [149].
  - `429 Too Many Requests`: Vượt quá giới hạn Rate Limit.
  - `500 Internal Server Error`: Lỗi hệ thống ngoài dự kiến [149].

---

## 2. KIẾN TRÚC MÔ HÌNH BẢO MẬT SSO & SLO VỚI SPRING BOOT & REDIS [45-48]

### 2.1 Mô hình Tách biệt Auth Service & Resource Server [47, 48]
Theo tài liệu kiến trúc JWT SSO/SLO, hệ thống bao gồm 3 thành phần chính:
1. **Authentication Service (Auth Server - Port 8080):** [47]
   - Tiếp nhận thông tin Đăng nhập.
   - Truy vấn Database xác thực credentials.
   - Sử dụng Private Key RSA (RS256) để ký phát hành JWT Access Token + Refresh Token [50].
2. **Resource Service (Product Catalog API - Port 8180/8280):** [48]
   - Độc lập hoàn toàn với Auth Server.
   - Nhận Public Key RSA (`.well-known/jwks.json` hoặc file PEM) để xác minh chữ ký JWT hoàn toàn **Stateless** [46, 52].
   - Trích xuất claim `roles` thành `GrantedAuthority` để phân quyền ứng dụng [57].
3. **Redis Central Store (Port 6379):** [48]
   - Lưu trữ danh sách **Token Blacklist (SLO)** cho các Token bị ngắt phiên đăng xuất tức thì [48, 52, 53].
   - Giúp vô hiệu hóa Token ngay lập tức trước khi nó hết hạn TTL mà không làm ảnh hưởng đến tính chất Stateless của các request hợp lệ khác [48].

### 2.2 Sơ đồ Luồng Đăng xuất Đơn & Đăng xuất Hệ thống (SLO - Single Log-Out) [53, 54]
```text
[User Client] ---> (POST /api/auth/logout kèm JWT Access Token) ---> [Auth Service]
                                                                          |
                                                                    1. Đưa 'jti' vào Redis Blacklist
                                                                       (TTL = Token exp)
                                                                    2. Đánh dấu Refresh Token = REVOKED
                                                                          |
                                                                          v
                                                               [Redis Store: BLACKLIST_jti]
                                                                          |
[Resource Service A/B] <--- (Request tiếp theo mang JWT bị Logout) -------+
        |
    JwtDecoder check Redis: 'jti' nằm trong Blacklist? ---> CÓ ---> Trả 401 Unauthorized
```

### 2.3 Bảo mật Cookie & Token Transport Strategy [47, 50, 51, 56]
- Khi triển khai ứng dụng Web Client (SSR/SPA), Token không lưu tại `localStorage` (tránh nguy cơ XSS).
- Sử dụng **HttpOnly Cookie** với các cờ bảo mật [50, 51, 56]:
  - `HttpOnly = true` (Trình duyệt JavaScript không thể truy cập) [50, 51].
  - `Secure = true` (Bắt buộc truyền qua HTTPS) [47, 51, 56].
  - `SameSite = Strict` hoặc `Lax` (Chống tấn công CSRF) [56].

---

## 3. NGUYÊN TẮC PHÒNG THỦ NHIỀU LỚP (DEFENSE IN DEPTH) [24]

Hệ thống triển khai phân quyền tối thiểu 2 lớp:
1. **Lớp Filter Chain (Routing Security):** Đặt tại `SecurityFilterChain` chốt chặn các request HTTP theo URL Pattern (ví dụ: `.requestMatchers("/api/v1/products/**").hasRole("ADMIN")`) [15].
2. **Lớp Method Security (Business Method Security):** Đặt trực tiếp tại Java Service `@PreAuthorize("hasRole('ADMIN')")` hoặc `@PreAuthorize("hasAuthority('SCOPE_product:write')")` [24, 42].
   - *Lợi ích:* Đảm bảo nếu một phương thức Service được gọi nội bộ từ một Batch Job, Async Task hay Controller mới mà quên cấu hình SecurityFilterChain, hệ thống vẫn từ chối truy cập trái phép [24].
