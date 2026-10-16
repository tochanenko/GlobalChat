package com.tochanenko.beglobalchat.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bucket;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.Locale;

@Component
public class LoginRateLimiter {

    private static final int USER_LIMIT = 5;
    private static final int IP_LIMIT = 20;

    private static final Duration USER_PERIOD = Duration.ofMinutes(5);
    private static final Duration IP_PERIOD = Duration.ofMinutes(1);

    private final Cache<String, Bucket> userBuckets = Caffeine.newBuilder()
            .maximumSize(50_000)
            .expireAfterAccess(Duration.ofMinutes(15))
            .build();

    private final Cache<String, Bucket> ipBuckets = Caffeine.newBuilder()
            .maximumSize(50_000)
            .expireAfterAccess(Duration.ofMinutes(3))
            .build();

    public void check(String username, String ipAddress) {
        String normalisedUsername = username.toLowerCase(Locale.ROOT);

        Bucket userBucket = this.userBuckets.get(normalisedUsername, key -> createBucket(USER_LIMIT, USER_PERIOD));
        Bucket ipBucket = this.ipBuckets.get(ipAddress, key -> createBucket(IP_LIMIT, IP_PERIOD));

        if (!ipBucket.tryConsume(1)) rejectRequest();
        if (!userBucket.tryConsume(1)) rejectRequest();
    }

    private static Bucket createBucket(int capacity, Duration refillPeriod) {
        return Bucket.builder()
                .addLimit(limit -> limit.capacity(capacity).refillGreedy(capacity, refillPeriod))
                .build();
    }

    private static void rejectRequest() {
        throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many requests. Try again later.");
    }

}
