package dev.forgepack.security.internal.configuration;

import dev.forgepack.authentication.internal.configuration.filter.JwtFilter;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConfigurationSecurityTest {

    @Test
    void createsSecuritySupportBeans() throws Exception {
        ConfigurationSecurity configuration = new ConfigurationSecurity(mock(JwtFilter.class), endpointProperties());
        AuthenticationManager manager = mock(AuthenticationManager.class);
        AuthenticationConfiguration authenticationConfiguration = mock(AuthenticationConfiguration.class);
        when(authenticationConfiguration.getAuthenticationManager()).thenReturn(manager);

        GrantedAuthorityDefaults authorityDefaults = configuration.grantedAuthorityDefaults();
        PasswordEncoder passwordEncoder = configuration.passwordEncoder();

        assertThat(authorityDefaults.getRolePrefix()).isEmpty();
        assertThat(passwordEncoder.matches("secret", passwordEncoder.encode("secret"))).isTrue();
        assertThat(configuration.authenticationManager(authenticationConfiguration)).isSameAs(manager);
    }

    @Test
    void mergesBuiltInAndAdditionalEndpointPatterns() throws Exception {
        Method merge = ConfigurationSecurity.class.getDeclaredMethod("merge", List.class, List.class);
        merge.setAccessible(true);
        Method toArray = ConfigurationSecurity.class.getDeclaredMethod("toArray", List.class);
        toArray.setAccessible(true);

        @SuppressWarnings("unchecked")
        List<String> unchanged = (List<String>) merge.invoke(null, List.of("/built-in"), null);
        @SuppressWarnings("unchecked")
        List<String> merged = (List<String>) merge.invoke(null, List.of("/built-in"), List.of("/custom"));
        @SuppressWarnings("unchecked")
        java.util.Optional<String[]> empty = (java.util.Optional<String[]>) toArray.invoke(null, List.of());
        @SuppressWarnings("unchecked")
        java.util.Optional<String[]> patterns = (java.util.Optional<String[]>) toArray.invoke(null, merged);

        assertThat(unchanged).containsExactly("/built-in");
        assertThat(merged).containsExactly("/built-in", "/custom");
        assertThat(empty).isEmpty();
        assertThat(patterns).hasValueSatisfying(values -> assertThat(values).containsExactly("/built-in", "/custom"));
    }

    private static PropertiesSecurityEndpoints endpointProperties() {
        return new PropertiesSecurityEndpoints(List.of(), List.of(), List.of());
    }
}