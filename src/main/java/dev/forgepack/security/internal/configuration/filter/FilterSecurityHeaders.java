package dev.forgepack.security.internal.configuration.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Servlet filter that applies HTTP security headers and Content Security Policy
 * on every request, routing to the appropriate policy based on the request URI.
 *
 * <p>All policies are configurable via {@code application.properties} under the
 * {@code forgepack.security.*} prefix. See {@link PropertiesSecurityHeaders}.</p>
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 */
@Component
public class FilterSecurityHeaders extends OncePerRequestFilter {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final PropertiesSecurityHeaders props;
    private final BuildProperties buildProperties;

    public FilterSecurityHeaders(PropertiesSecurityHeaders props, Optional<BuildProperties> buildProperties) {
        this.props = props;
        this.buildProperties = buildProperties.orElse(null);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        applyBaseHeaders(response);
        applyHsts(response);
        applyRouteHeaders(request, response);
        chain.doFilter(request, response);
    }

    private void applyBaseHeaders(HttpServletResponse response) {
        PropertiesSecurityHeaders.Headers h = props.headers();
        response.setHeader("X-Content-Type-Options", h.xContentTypeOptions());
        response.setHeader("X-Frame-Options",        h.xFrameOptions());
        response.setHeader("X-XSS-Protection",       h.xXssProtection());
        response.setHeader("Referrer-Policy",         h.referrerPolicy());
        response.setHeader("X-API-Version", resolveBuildVersion());
    }

    private void applyHsts(HttpServletResponse response) {
        PropertiesSecurityHeaders.Headers.Hsts hsts = props.headers().hsts();
        if (!hsts.enabled()) return;
        String value = "max-age=" + hsts.maxAge() + (hsts.includeSubDomains() ? "; includeSubDomains" : "");
        response.setHeader("Strict-Transport-Security", value);
    }

    private void applyRouteHeaders(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();

        if (matchesAny(uri, props.routes().apiPrefixes())) {
            response.setHeader("Content-Security-Policy", buildApiCsp());
            response.setHeader("Cache-Control", props.cache().api());
            response.setHeader("Pragma", "no-cache");

        } else if (matchesAny(uri, props.routes().actuatorPrefixes())) {
            response.setHeader("Content-Security-Policy", props.csp().actuator());
            response.setHeader("Cache-Control", props.cache().actuator());
            response.setHeader("Pragma", "no-cache");

        } else {
            String nonce = generateNonce();
            response.setHeader("Content-Security-Policy", buildWebCsp(nonce));
            response.setHeader("Cache-Control", props.cache().web());
            request.setAttribute("cspNonce", nonce);
        }
    }

    private String buildApiCsp() {
        PropertiesSecurityHeaders.Csp.Api api = props.csp().api();
        return String.join("; ",
                "default-src "     + api.defaultSrc(),
                "frame-ancestors " + api.frameAncestors(),
                "connect-src "     + api.connectSrc(),
                "script-src 'none'",
                "style-src 'none'",
                "base-uri 'none'"
        );
    }

    private String buildWebCsp(String nonce) {
        // 'unsafe-inline' is kept for pre-CSP3 browser compatibility.
        // Modern browsers ignore 'unsafe-inline' when a valid nonce is present.
        PropertiesSecurityHeaders.Csp.Web web = props.csp().web();
        return String.join("; ",
                "default-src "     + web.defaultSrc(),
                "script-src "      + web.scriptSrc()  + " 'nonce-" + nonce + "' 'unsafe-inline'",
                "style-src "       + web.styleSrc()   + " 'nonce-" + nonce + "' 'unsafe-inline'",
                "img-src "         + web.imgSrc(),
                "font-src "        + web.fontSrc(),
                "connect-src "     + web.connectSrc(),
                "frame-ancestors " + web.frameAncestors(),
                "base-uri 'self'",
                "form-action 'self'"
        );
    }

    private boolean matchesAny(String uri, List<String> prefixes) {
        return prefixes.stream().anyMatch(uri::startsWith);
    }

    private static String generateNonce() {
        byte[] bytes = new byte[16];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private String resolveBuildVersion() {
        if (buildProperties == null) return "unknown";
        return buildProperties.getVersion();
    }
}