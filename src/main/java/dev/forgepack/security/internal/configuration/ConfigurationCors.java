package dev.forgepack.security.internal.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Configures CORS (Cross-Origin Resource Sharing) for the application.
 *
 * <p>All parameters are configurable via {@code application.properties} under the
 * {@code forgepack.cors} prefix. See {@link PropertiesCors}.</p>
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 */
@Configuration
public class ConfigurationCors {

    private final PropertiesCors props;

    public ConfigurationCors(PropertiesCors props) {
        this.props = props;
    }

    /**
     * Builds a {@link CorsConfigurationSource} applied to all paths ({@code /**}).
     *
     * @return the configured {@link CorsConfigurationSource} bean
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(props.allowedOrigins());
        configuration.setAllowedMethods(props.allowedMethods());
        configuration.setAllowedHeaders(props.allowedHeaders());
        configuration.setAllowCredentials(props.allowCredentials());
        configuration.setMaxAge(props.maxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}