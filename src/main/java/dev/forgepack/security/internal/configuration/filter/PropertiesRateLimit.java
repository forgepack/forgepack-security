package dev.forgepack.security.internal.configuration.filter;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for the rate limiting filter.
 *
 * <p>Configurable via {@code application.properties} under the {@code forgepack.rate-limit}
 * prefix. All fields have sensible defaults and may be omitted by the consumer.</p>
 *
 * @param requestsPerMinute          Sustained request rate per client per minute. Default: 100.
 * @param burstMultiplier            Multiplier over the sustained rate that defines the bucket capacity. Default: 2.
 * @param cleanupIntervalMinutes     Interval in minutes between cache cleanup runs. Default: 15.
 * @param cleanupThresholdMultiplier Multiplier over the cleanup interval that defines the minimum inactivity
 *                                   time before a bucket is evicted. Default: 2.
 * @param trustForwardedFor          When {@code true}, uses the {@code X-Forwarded-For} header to resolve
 *                                   the client IP. Enable only behind a trusted reverse proxy. Default: false.
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 */
@Validated
@ConfigurationProperties(prefix = "forgepack.rate-limit")
public record PropertiesRateLimit(
        @Min(1) int requestsPerMinute,
        @Min(1) int burstMultiplier,
        @Min(1) int cleanupIntervalMinutes,
        @Min(1) int cleanupThresholdMultiplier,
        boolean trustForwardedFor
) {
    public PropertiesRateLimit() {
        this(100, 2, 15, 2, false);
    }
}