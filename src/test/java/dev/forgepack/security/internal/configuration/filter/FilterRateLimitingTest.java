package dev.forgepack.security.internal.configuration.filter;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class FilterRateLimitingTest {

    @Test
    void permitsRequestsUntilTheBucketIsEmptyAndThenReturns429() throws Exception {
        FilterRateLimiting filter = new FilterRateLimiting(new PropertiesRateLimit(2, 1, 1, 1, false));

        MockHttpServletResponse first = filterResponse(filter, request("10.0.0.1"));
        MockHttpServletResponse second = filterResponse(filter, request("10.0.0.1"));
        MockHttpServletResponse limited = filterResponse(filter, request("10.0.0.1"));

        assertThat(first.getHeader("X-RateLimit-Limit")).isEqualTo("2");
        assertThat(second.getHeader("X-RateLimit-Remaining")).isEqualTo("0");
        assertThat(limited.getStatus()).isEqualTo(429);
        assertThat(limited.getHeader("Retry-After")).isNotBlank();
        assertThat(limited.getContentAsString()).contains("Rate limit exceeded");
    }

    @Test
    void usesForwardedClientAddressWhenConfigured() throws Exception {
        FilterRateLimiting filter = new FilterRateLimiting(new PropertiesRateLimit(1, 1, 1, 1, true));
        MockHttpServletRequest first = request("10.0.0.1");
        first.addHeader("X-Forwarded-For", "203.0.113.1, 10.0.0.1");
        MockHttpServletRequest second = request("10.0.0.1");
        second.addHeader("X-Forwarded-For", "203.0.113.2");

        assertThat(filterResponse(filter, first).getStatus()).isEqualTo(200);
        assertThat(filterResponse(filter, second).getStatus()).isEqualTo(200);
    }

    @Test
    void fallsBackToRealIpAndRemoteAddressWhenForwardedIpIsUnavailable() throws Exception {
        FilterRateLimiting filter = new FilterRateLimiting(new PropertiesRateLimit(1, 1, 1, 1, true));
        MockHttpServletRequest realIpRequest = request("10.0.0.1");
        realIpRequest.addHeader("X-Forwarded-For", " ");
        realIpRequest.addHeader("X-Real-IP", "203.0.113.1");
        MockHttpServletRequest remoteAddressRequest = request("10.0.0.1");

        assertThat(filterResponse(filter, realIpRequest).getStatus()).isEqualTo(200);
        assertThat(filterResponse(filter, remoteAddressRequest).getStatus()).isEqualTo(200);
    }

    @Test
    void startsAndStopsTheCleanupScheduler() {
        FilterRateLimiting filter = new FilterRateLimiting(new PropertiesRateLimit(1, 1, 1, 1, false));

        filter.init();
        filter.destroy();
    }

    @Test
    void safelyDestroysAnUninitializedFilter() {
        new FilterRateLimiting(new PropertiesRateLimit()).destroy();
    }

    private static MockHttpServletRequest request(String remoteAddress) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders");
        request.setRemoteAddr(remoteAddress);
        return request;
    }

    private static MockHttpServletResponse filterResponse(FilterRateLimiting filter, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }
}