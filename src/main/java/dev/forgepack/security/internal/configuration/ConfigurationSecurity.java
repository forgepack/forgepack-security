package dev.forgepack.security.internal.configuration;

import dev.forgepack.authentication.internal.configuration.JwtConfiguration;
import dev.forgepack.authentication.internal.configuration.filter.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * Spring Security configuration for the application.
 *
 * <p>Configures a stateless, JWT-based security model with the following characteristics:</p>
 * <ul>
 *     <li>CSRF disabled (REST API with stateless sessions)</li>
 *     <li>Security headers delegated entirely to {@link dev.forgepack.security.internal.configuration.filter.FilterSecurityHeaders}</li>
 *     <li>Public endpoints driven by {@link PropertiesSecurityEndpoints} — configurable via
 *         {@code forgepack.security.endpoints.*} properties</li>
 *     <li>All other requests require authentication</li>
 *     <li>{@link JwtFilter} inserted before {@link UsernamePasswordAuthenticationFilter}</li>
 *     <li>Role prefix removed via {@link GrantedAuthorityDefaults}</li>
 * </ul>
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 *
 * @see JwtFilter
 * @see JwtConfiguration
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ConfigurationSecurity {

    private static final List<String> BUILT_IN_PERMIT_ALL  = List.of(
            "/actuator/health", "/actuator/info",
            "/api/v1/auth/**", "/v3/api-docs/**", "/swagger-ui/**"
    );
    private static final List<String> BUILT_IN_PERMIT_POST = List.of("/auth/login", "/user/**");
    private static final List<String> BUILT_IN_PERMIT_PUT  = List.of("/auth/resetPassword");

    private final JwtFilter filterJwt;
    private final PropertiesSecurityEndpoints endpointProps;

    public ConfigurationSecurity(JwtFilter filterJwt, PropertiesSecurityEndpoints endpointProps) {
        this.filterJwt      = filterJwt;
        this.endpointProps  = endpointProps;
    }
    /**
     * Defines the main {@link SecurityFilterChain} with authorization rules,
     * security headers, and the JWT filter.
     *
     * @param httpSecurity the {@link HttpSecurity} builder
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain apiFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .securityMatcher("/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                        toArray(merge(BUILT_IN_PERMIT_ALL,  endpointProps.permitAll())) .ifPresent(p -> auth.requestMatchers(p).permitAll());
                        toArray(merge(BUILT_IN_PERMIT_POST, endpointProps.permitPost())).ifPresent(p -> auth.requestMatchers(HttpMethod.POST, p).permitAll());
                        toArray(merge(BUILT_IN_PERMIT_PUT,  endpointProps.permitPut())) .ifPresent(p -> auth.requestMatchers(HttpMethod.PUT,  p).permitAll());
                        auth.anyRequest().authenticated();
                })
                .addFilterBefore(filterJwt, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
    /**
     * Removes the default {@code ROLE_} prefix from granted authorities,
     * allowing role names to be used without the prefix in security expressions.
     *
     * @return a {@link GrantedAuthorityDefaults} with an empty prefix
     */
    @Bean
    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("");
    }
    /**
     * Exposes the {@link AuthenticationManager} bean from the application context.
     *
     * @param authenticationConfiguration the Spring Security authentication configuration
     * @return the configured {@link AuthenticationManager}
     * @throws Exception if the manager cannot be resolved
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    /**
     * Provides the {@link PasswordEncoder} bean using BCrypt hashing.
     *
     * @return a {@link BCryptPasswordEncoder} instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private static List<String> merge(List<String> builtIn, List<String> extra) {
        if (extra == null || extra.isEmpty()) return builtIn;
        List<String> merged = new ArrayList<>(builtIn);
        merged.addAll(extra);
        return merged;
    }

    private static java.util.Optional<String[]> toArray(List<String> list) {
        if (list == null || list.isEmpty()) return java.util.Optional.empty();
        return java.util.Optional.of(list.toArray(String[]::new));
    }
}
