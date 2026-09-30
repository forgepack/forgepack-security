package dev.forgepack.security.internal.configuration.filter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;
import java.util.Optional;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

class FilterSecurityHeadersTest {

    @Test
    void appliesApiHeadersAndEnabledHsts() throws Exception {
        FilterSecurityHeaders filter = new FilterSecurityHeaders(properties(true), Optional.of(buildProperties()));
        MockHttpServletResponse response = filterResponse("/api/orders", filter);

        assertThat(response.getHeader("X-API-Version")).isEqualTo("1.2.3");
        assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo("max-age=60; includeSubDomains");
        assertThat(response.getHeader("Content-Security-Policy"))
                .isEqualTo("default-src 'none'; frame-ancestors 'none'; connect-src 'self'; script-src 'none'; style-src 'none'; base-uri 'none'");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeader("Pragma")).isEqualTo("no-cache");
    }

    @Test
    void appliesActuatorPolicyWithoutHsts() throws Exception {
        FilterSecurityHeaders filter = new FilterSecurityHeaders(properties(false), Optional.empty());
        MockHttpServletResponse response = filterResponse("/actuator/health", filter);

        assertThat(response.getHeader("X-API-Version")).isEqualTo("unknown");
        assertThat(response.getHeader("Strict-Transport-Security")).isNull();
        assertThat(response.getHeader("Content-Security-Policy")).isEqualTo("default-src 'none'");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    void appliesWebPolicyWithRequestNonce() throws Exception {
        FilterSecurityHeaders filter = new FilterSecurityHeaders(properties(false), Optional.empty());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        String nonce = (String) request.getAttribute("cspNonce");
        assertThat(nonce).matches("[A-Za-z0-9+/]{22}==");
        assertThat(response.getHeader("Content-Security-Policy")).contains("'nonce-" + nonce + "'");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("private");
    }

    private static MockHttpServletResponse filterResponse(String uri, FilterSecurityHeaders filter) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private static BuildProperties buildProperties() {
        Properties properties = new Properties();
        properties.setProperty("version", "1.2.3");
        return new BuildProperties(properties);
    }

    private static PropertiesSecurityHeaders properties(boolean hstsEnabled) {
        return new PropertiesSecurityHeaders(
                new PropertiesSecurityHeaders.Headers("nosniff", "DENY", "1", "strict-origin",
                        new PropertiesSecurityHeaders.Headers.Hsts(hstsEnabled, 60, true)),
                new PropertiesSecurityHeaders.Routes(List.of("/api/"), List.of("/actuator/")),
                new PropertiesSecurityHeaders.Csp("default-src 'none'",
                        new PropertiesSecurityHeaders.Csp.Api("'none'", "'none'", "'self'"),
                        new PropertiesSecurityHeaders.Csp.Web("'self'", "'self'", "'self'", "'self'", "'self'", "'self'", "'none'")),
                new PropertiesSecurityHeaders.Cache("no-store", "no-store", "private"));
    }
}