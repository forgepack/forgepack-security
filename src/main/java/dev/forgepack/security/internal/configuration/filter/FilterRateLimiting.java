package dev.forgepack.security.internal.configuration.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Servlet filter that enforces per-client rate limiting based on IP, URI, and HTTP method.
 *
 * <p>All parameters are configurable via {@code application.properties} under the
 * {@code forgepack.rate-limit} prefix:</p>
 *
 * <pre>
 * forgepack.rate-limit.requests-per-minute=100
 * forgepack.rate-limit.burst-multiplier=2
 * forgepack.rate-limit.cleanup-interval-minutes=15
 * forgepack.rate-limit.cleanup-threshold-multiplier=2
 * forgepack.rate-limit.trust-forwarded-for=false  # enable only behind a trusted reverse proxy
 * </pre>
 *
 * <p>{@code X-RateLimit-Limit} reflects the real bucket capacity (sustained rate × burst
 * multiplier). {@code X-RateLimit-Sustained} exposes the configured sustained rate.</p>
 *
 * <p><strong>Note:</strong> the last-access timestamp in {@link BucketEntry} is updated
 * on a best-effort basis under concurrency. Precision is sufficient for inactivity-based
 * cleanup purposes.</p>
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 */
@Component
public class FilterRateLimiting extends OncePerRequestFilter {

    private static final Logger       log           = LoggerFactory.getLogger(FilterRateLimiting.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final PropertiesRateLimit properties;
    private final ConcurrentMap<String, BucketEntry> cache = new ConcurrentHashMap<>();
    private ScheduledExecutorService scheduler;

    public FilterRateLimiting(PropertiesRateLimit properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "rate-limit-cleanup");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(
                this::cleanupCache,
                properties.cleanupIntervalMinutes(),
                properties.cleanupIntervalMinutes(),
                TimeUnit.MINUTES
        );
        log.info("Rate limiting initialized: requests={}/min, burst={}x, cleanup={}min, trustForwardedFor={}",
                properties.requestsPerMinute(),
                properties.burstMultiplier(),
                properties.cleanupIntervalMinutes(),
                properties.trustForwardedFor());
    }

    @PreDestroy
    public void destroy() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS))
                    log.warn("Rate limit cleanup scheduler did not terminate in time");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        cache.clear();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String clientId = getClientIdentifier(request);

        try {
            BucketEntry      entry = cache.computeIfAbsent(clientId, k -> new BucketEntry(createBucket()));
            ConsumptionProbe probe = entry.consume();

            addRateLimitHeaders(response, probe);

            if (probe.isConsumed()) chain.doFilter(request, response);
            else                    handleRateLimitExceeded(response, probe);

        } catch (Exception e) {
            log.error("Rate limiting error for {}: {}", clientId, e.getMessage(), e);
            chain.doFilter(request, response); // fail-open
        }
    }

    private String getClientIdentifier(HttpServletRequest request) {
        String ip = properties.trustForwardedFor()
                ? Optional.ofNullable(request.getHeader("X-Forwarded-For"))
                .filter(h -> !h.isBlank())
                .map(h -> h.split(",")[0].trim())
                .or(() -> Optional.ofNullable(request.getHeader("X-Real-IP")))
                .orElse(request.getRemoteAddr())
                : request.getRemoteAddr();

        return ip + ":" + request.getRequestURI() + ":" + request.getMethod();
    }

    private Bucket createBucket() {
        int tokens   = Math.max(properties.requestsPerMinute(), 1);
        int capacity = tokens * Math.max(properties.burstMultiplier(), 1);
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(capacity)
                        .refillGreedy(tokens, Duration.ofMinutes(1))
                        .build())
                .build();
    }

    private void addRateLimitHeaders(HttpServletResponse response, ConsumptionProbe probe) {
        int capacity = properties.requestsPerMinute() * properties.burstMultiplier();
        response.addHeader("X-RateLimit-Limit",     String.valueOf(capacity));
        response.addHeader("X-RateLimit-Sustained", String.valueOf(properties.requestsPerMinute()));
        response.addHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
        response.addHeader("X-RateLimit-Reset",     String.valueOf(probe.getNanosToWaitForRefill() / 1_000_000_000));
    }

    private void handleRateLimitExceeded(HttpServletResponse response, ConsumptionProbe probe) throws IOException {
        long retryAfter = probe.getNanosToWaitForRefill() / 1_000_000_000;
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.addHeader("Retry-After", String.valueOf(retryAfter));
        response.getWriter().write(OBJECT_MAPPER.writeValueAsString(Map.of(
                "status",  HttpStatus.TOO_MANY_REQUESTS.value(),
                "error",   "Too Many Requests",
                "message", "Rate limit exceeded. Please try again in " + retryAfter + " seconds."
        )));
    }

    private void cleanupCache() {
        Duration threshold = Duration.ofMinutes((long) properties.cleanupIntervalMinutes() * properties.cleanupThresholdMultiplier());
        Instant  cutoff    = Instant.now().minus(threshold);
        int      before    = cache.size();
        cache.entrySet().removeIf(e -> e.getValue().lastAccess().isBefore(cutoff));
        log.debug("Rate limit cache cleanup: {} → {} entries", before, cache.size());
    }

    /**
     * Holds a {@link Bucket} together with a last-access timestamp for inactivity-based cleanup.
     *
     * <p>{@code lastAccess} is updated on a best-effort basis: {@code volatile} ensures
     * visibility but not atomicity with the bucket consumption. This precision is sufficient
     * for cleanup purposes.</p>
     */
    private static final class BucketEntry {
        private final Bucket         bucket;
        private volatile Instant     lastAccess;

        BucketEntry(Bucket bucket) {
            this.bucket     = bucket;
            this.lastAccess = Instant.now();
        }

        ConsumptionProbe consume() {
            lastAccess = Instant.now();
            return bucket.tryConsumeAndReturnRemaining(1);
        }

        Instant lastAccess() { return lastAccess; }
    }
}