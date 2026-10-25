package com.fptaptech.catalog.auth;

import com.fptaptech.catalog.product.Product;
import com.fptaptech.catalog.product.ProductRepository;
import com.fptaptech.catalog.user.AppUser;
import com.fptaptech.catalog.user.Role;
import com.fptaptech.catalog.user.RoleRepository;
import com.fptaptech.catalog.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Set;

@Component
public class AdminSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminSeeder.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ProductRepository productRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.seed-admin.enabled:true}")
    private boolean seedEnabled;

    @Value("${app.seed-admin.username:admin}")
    private String adminUsername;

    @Value("${app.seed-admin.password:DefaultAdminPass2026}")
    private String adminPassword;

    public AdminSeeder(UserRepository userRepository,
                       RoleRepository roleRepository,
                       ProductRepository productRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.productRepository = productRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(String... args) {
        Role roleUser = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_USER").build()));

        Role roleAdmin = roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_ADMIN").build()));

        if (seedEnabled) {
            // Seed Admin
            if (!userRepository.existsByUsername(adminUsername)) {
                Instant now = Instant.now();
                AppUser admin = AppUser.builder()
                        .username(adminUsername)
                        .passwordHash(passwordEncoder.encode(adminPassword))
                        .tokenVersion(0L)
                        .createdAt(now)
                        .updatedAt(now)
                        .roles(Set.of(roleUser, roleAdmin))
                        .build();
                userRepository.save(admin);
                log.info("Đã khởi tạo tài khoản ADMIN mặc định: {} (Roles: ROLE_USER, ROLE_ADMIN)", adminUsername);
            }

            // Seed Regular User for testing permissions
            if (!userRepository.existsByUsername("user")) {
                Instant now = Instant.now();
                AppUser regularUser = AppUser.builder()
                        .username("user")
                        .passwordHash(passwordEncoder.encode("UserPass2026"))
                        .tokenVersion(0L)
                        .createdAt(now)
                        .updatedAt(now)
                        .roles(Set.of(roleUser))
                        .build();
                userRepository.save(regularUser);
                log.info("Đã khởi tạo tài khoản USER thông thường: user (Role: ROLE_USER)");
            }
        }

        // Seed Sample Products if empty
        if (productRepository.count() == 0) {
            Instant now = Instant.now();
            productRepository.save(Product.builder()
                    .name("Bàn phím cơ Wireless RGB Pro")
                    .description("Switch cơ quang học, kết nối Bluetooth 5.2 và 2.4Ghz siêu nhạy")
                    .price(new BigDecimal("1850000.00"))
                    .createdAt(now)
                    .updatedAt(now)
                    .build());

            productRepository.save(Product.builder()
                    .name("Chuột công thái học Ergonomic Master 3S")
                    .description("Cảm biến 8000 DPI, cuộn MagSpeed siêu tốc, pin 70 ngày")
                    .price(new BigDecimal("2290000.00"))
                    .createdAt(now)
                    .updatedAt(now)
                    .build());

            productRepository.save(Product.builder()
                    .name("Màn hình 4K UltraSharp 27 inch Type-C")
                    .description("Độ phân giải 3840x2160, IPS 100% sRGB, cấp nguồn 90W qua Type-C")
                    .price(new BigDecimal("11500000.00"))
                    .createdAt(now)
                    .updatedAt(now)
                    .build());
            log.info("Đã khởi tạo dữ liệu sản phẩm mẫu Catalog ban đầu");
        }
    }
}
