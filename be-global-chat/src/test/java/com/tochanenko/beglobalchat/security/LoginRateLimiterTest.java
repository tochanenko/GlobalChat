package com.tochanenko.beglobalchat.security;

import org.assertj.core.api.ThrowableAssert;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.assertj.core.api.AssertionsForClassTypes.*;

public class LoginRateLimiterTest {

    private final LoginRateLimiter limiter = new LoginRateLimiter();

    @Test
    void allowsFiveRapidAttemptsForSameUsername() {
        for (int i = 0; i < 5; i++) {
            String ip = "192.0.1." + i;

            assertThatCode(() -> limiter.check("user", ip)).doesNotThrowAnyException();
        }
    }

    @Test
    void rejectsSixthRapidAttemptForSameUsername() {
        for (int i = 0; i < 5; i++) {
            limiter.check("user", "192.0.1." + i);
        }

        assertRateLimited(() -> limiter.check("user", "192.0.1.128"));
    }

    @Test
    void usernamesAreCaseInsensitive() {
        for (int i = 0; i < 5; i++) {
            limiter.check("User", "192.0.1." + i);
        }

        assertRateLimited(() -> limiter.check("USER", "192.0.1.128"));
    }

    @Test
    void rejectsTwentyFirstRapidAttemptForSameIp() {
        String ip = "192.0.1.1";

        for (int i = 0; i < 20; i++) {
            limiter.check("user_" + i, ip);
        }

        assertRateLimited(() -> limiter.check("another_user", ip));
    }

    @Test
    void concurrentRequestsCannotExceedUsernameLimit() {
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        IntStream.range(0, 40).parallel().forEach(i -> {
            try {
                limiter.check("target_user", "192.0.1." + i);
                allowed.incrementAndGet();
            } catch (ResponseStatusException ex) {
                assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                rejected.incrementAndGet();
            }
        });

        assertThat(allowed.get()).isEqualTo(5);
        assertThat(rejected.get()).isEqualTo(35);
    }

    private void assertRateLimited(ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(
                ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS)
        );
    }

}
