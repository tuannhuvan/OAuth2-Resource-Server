package com.fptaptech.catalog.common;

import java.util.List;

public class ApiResponse {

    public record Single<T>(T data) {}

    public record Pagination(
            long total,
            int per_page,
            int current_page,
            int total_pages
    ) {}

    public record Collection<T>(List<T> data, Pagination pagination) {}
}
