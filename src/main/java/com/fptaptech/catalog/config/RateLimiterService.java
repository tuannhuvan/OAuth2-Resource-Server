package com.fptaptech.catalog.config;

import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimiterService {

    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final long WINDOW_MILLIS = 60_000L;

    private final Map<String, Deque<Long>> ipRequestTimestamps = new ConcurrentHashMap<>();

    public synchronized boolean allowRequest(String clientIp) {
        long now = System.currentTimeMillis();
        long windowStart = now - WINDOW_MILLIS;

        Deque<Long> timestamps = ipRequestTimestamps.computeIfAbsent(clientIp, k -> new ArrayDeque<>());

        // Evict expired timestamps
        while (!timestamps.isEmpty() && timestamps.peekFirst() <= windowStart) {
            timestamps.pollFirst();
        }

        if (timestamps.size() >= MAX_REQUESTS_PER_MINUTE) {
            return false;
        }

        timestamps.addLast(now);
        return true;
    }

    public synchronized void reset() {
        ipRequestTimestamps.clear();
    }
}
