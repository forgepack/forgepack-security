package dev.forgepack.security.internal.configuration.filter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

/**
 * Configuration properties for HTTP security headers and Content Security Policy.
 *
 * <p>Configurable via {@code application.properties} under the {@code forgepack.security} prefix.
 * All fields have sensible defaults and may be omitted by the consumer.</p>
 *
 * <p>Nested records annotated with bare {@code @DefaultValue} instruct the Spring Boot binder
 * to instantiate them using their own field-level defaults when no value is provided.</p>
 *
 * @param headers Base security response headers (X-Content-Type-Options, X-Frame-Options, etc.).
 * @param routes  URI prefix lists used to determine which CSP and cache policy to apply.
 * @param csp     Content Security Policy directives per route type.
 * @param cache   Cache-Control header values per route type.
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 */
@ConfigurationProperties(prefix = "forgepack.security")
public record PropertiesSecurityHeaders(
        @DefaultValue Headers headers,
        @DefaultValue Routes  routes,
        @DefaultValue Csp     csp,
        @DefaultValue Cache   cache
) {

    /**
     * Base HTTP security response headers applied to every request.
     *
     * @param xContentTypeOptions Value for {@code X-Content-Type-Options}. Default: {@code nosniff}.
     * @param xFrameOptions       Value for {@code X-Frame-Options}. Default: {@code DENY}.
     * @param xXssProtection      Value for {@code X-XSS-Protection}. Default: {@code 1; mode=block}.
     * @param referrerPolicy      Value for {@code Referrer-Policy}. Default: {@code strict-origin-when-cross-origin}.
     * @param hsts                HTTP Strict Transport Security configuration.
     */
    public record Headers(
            @DefaultValue("nosniff")                         String xContentTypeOptions,
            @DefaultValue("DENY")                            String xFrameOptions,
            @DefaultValue("1; mode=block")                   String xXssProtection,
            @DefaultValue("strict-origin-when-cross-origin") String referrerPolicy,
            @DefaultValue Hsts hsts
    ) {
        /**
         * HTTP Strict Transport Security (HSTS) configuration.
         *
         * @param enabled           Whether to emit the {@code Strict-Transport-Security} header. Default: {@code false}.
         * @param maxAge            Max age in seconds. Default: {@code 31536000} (1 year).
         * @param includeSubDomains Whether to include the {@code includeSubDomains} directive. Default: {@code true}.
         */
        public record Hsts(
                @DefaultValue("false")    boolean enabled,
                @DefaultValue("31536000") long    maxAge,
                @DefaultValue("true")     boolean includeSubDomains
        ) {}
    }

    /**
     * URI prefix lists used to route requests to the appropriate CSP and cache policy.
     *
     * @param apiPrefixes      Prefixes matched against the request URI to apply the API policy.
     *                         Default: {@code /api/}, {@code /auth/}.
     * @param actuatorPrefixes Prefixes matched against the request URI to apply the actuator policy.
     *                         Default: {@code /actuator/}.
     */
    public record Routes(
            @DefaultValue({"/api/", "/auth/"}) List<String> apiPrefixes,
            @DefaultValue({"/actuator/"})      List<String> actuatorPrefixes
    ) {}

    /**
     * Content Security Policy directives per route type.
     *
     * @param actuator Full CSP header value applied to actuator routes. Default: {@code default-src 'none'}.
     * @param api      CSP directives applied to API routes.
     * @param web      CSP directives applied to web (non-API, non-actuator) routes.
     */
    public record Csp(
            @DefaultValue("default-src 'none'") String actuator,
            @DefaultValue Api api,
            @DefaultValue Web web
    ) {
        /**
         * CSP directives for API routes.
         *
         * @param defaultSrc     Value for {@code default-src}. Default: {@code 'none'}.
         * @param frameAncestors Value for {@code frame-ancestors}. Default: {@code 'none'}.
         * @param connectSrc     Value for {@code connect-src}. Default: {@code 'self'}.
         */
        public record Api(
                @DefaultValue("'none'") String defaultSrc,
                @DefaultValue("'none'") String frameAncestors,
                @DefaultValue("'self'") String connectSrc
        ) {}

        /**
         * CSP directives for web routes. A per-request nonce is appended to
         * {@code script-src} and {@code style-src} at runtime.
         *
         * @param defaultSrc     Value for {@code default-src}. Default: {@code 'self'}.
         * @param scriptSrc      Base value for {@code script-src}. Default: {@code 'self'}.
         * @param styleSrc       Base value for {@code style-src}. Default: {@code 'self' https://fonts.googleapis.com}.
         * @param imgSrc         Value for {@code img-src}. Default: {@code 'self' data: https:}.
         * @param fontSrc        Value for {@code font-src}. Default: {@code 'self' https://fonts.gstatic.com}.
         * @param connectSrc     Value for {@code connect-src}. Default: {@code 'self'}.
         * @param frameAncestors Value for {@code frame-ancestors}. Default: {@code 'none'}.
         */
        public record Web(
                @DefaultValue("'self'")                              String defaultSrc,
                @DefaultValue("'self'")                              String scriptSrc,
                @DefaultValue("'self' https://fonts.googleapis.com") String styleSrc,
                @DefaultValue("'self' data: https:")                 String imgSrc,
                @DefaultValue("'self' https://fonts.gstatic.com")    String fontSrc,
                @DefaultValue("'self'")                              String connectSrc,
                @DefaultValue("'none'")                              String frameAncestors
        ) {}
    }

    /**
     * Cache-Control header values per route type.
     *
     * @param api      Cache-Control for API routes. Default: {@code no-store, no-cache, must-revalidate}.
     * @param actuator Cache-Control for actuator routes. Default: {@code no-store, no-cache, must-revalidate}.
     * @param web      Cache-Control for web routes. Default: {@code no-cache, private}.
     */
    public record Cache(
            @DefaultValue("no-store, no-cache, must-revalidate") String api,
            @DefaultValue("no-store, no-cache, must-revalidate") String actuator,
            @DefaultValue("no-cache, private")                   String web
    ) {}
}