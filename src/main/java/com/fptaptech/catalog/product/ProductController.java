package com.fptaptech.catalog.product;

import com.fptaptech.catalog.common.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/products")
@Tag(name = "Product Catalog", description = "Quản lý danh mục sản phẩm (Đọc Public, Ghi yêu cầu ROLE_ADMIN)")
public class ProductController {

    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    @Operation(summary = "Xem danh sách sản phẩm (Public)", description = "Không yêu cầu JWT token")
    public ApiResponse.Collection<ProductResponse> getAllProducts() {
        List<ProductResponse> list = productService.findAll();
        ApiResponse.Pagination pagination = new ApiResponse.Pagination(list.size(), 10, 1, Math.max(1, (int) Math.ceil((double) list.size() / 10)));
        return new ApiResponse.Collection<>(list, pagination);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Xem chi tiết sản phẩm (Public)", description = "Không yêu cầu JWT token")
    public ApiResponse.Single<ProductResponse> getProductById(@PathVariable Long id) {
        return new ApiResponse.Single<>(productService.findById(id));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Tạo mới sản phẩm (ROLE_ADMIN)", description = "Yêu cầu JWT Token có vai trò ROLE_ADMIN")
    public ResponseEntity<ApiResponse.Single<ProductResponse>> createProduct(@Valid @RequestBody ProductRequest request) {
        ProductResponse created = productService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(new ApiResponse.Single<>(created));
    }

    @PutMapping("/{id}")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Cập nhật sản phẩm (ROLE_ADMIN)", description = "Yêu cầu JWT Token có vai trò ROLE_ADMIN")
    public ApiResponse.Single<ProductResponse> updateProduct(@PathVariable Long id, @Valid @RequestBody ProductRequest request) {
        return new ApiResponse.Single<>(productService.update(id, request));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Xóa sản phẩm (ROLE_ADMIN)", description = "Yêu cầu JWT Token có vai trò ROLE_ADMIN")
    public void deleteProduct(@PathVariable Long id) {
        productService.delete(id);
    }
}
