package com.fptaptech.catalog.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";
        return new OpenAPI()
                .info(new Info()
                        .title("Catalog REST API - Spring Security 7 OAuth2 Resource Server")
                        .version("2.0.0")
                        .description("Hệ thống bảo vệ REST API bằng JSON Web Token (RS256 bất đối xứng) tích hợp Refresh Token Rotation, Reuse Detection, Single/All Logout, Rate Limiting và Key Rotation.")
                        .contact(new Contact().name("Senior Business Analyst & Security Team").email("ba-team@fptaptech.edu.vn"))
                        .license(new License().name("Apache 2.0").url("https://spring.io/projects/spring-security")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Nhập JWT Access Token vào đây (không cần gõ tiền tố 'Bearer ')")));
    }
}
