package dev.forgepack.security.internal.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigurationCorsTest {

    @Test
    void createsCorsConfigurationForEveryPath() {
        PropertiesCors properties = new PropertiesCors(
                List.of("https://app.example"), List.of("GET", "POST"),
                List.of("Authorization"), true, 900);

        CorsConfigurationSource source = new ConfigurationCors(properties).corsConfigurationSource();
        CorsConfiguration configuration = source.getCorsConfiguration(new MockHttpServletRequest("OPTIONS", "/orders"));

        assertThat(configuration.getAllowedOriginPatterns()).containsExactly("https://app.example");
        assertThat(configuration.getAllowedMethods()).containsExactly("GET", "POST");
        assertThat(configuration.getAllowedHeaders()).containsExactly("Authorization");
        assertThat(configuration.getAllowCredentials()).isTrue();
        assertThat(configuration.getMaxAge()).isEqualTo(900);
    }
}