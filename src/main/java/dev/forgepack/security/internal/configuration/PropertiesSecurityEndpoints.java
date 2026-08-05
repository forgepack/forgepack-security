package dev.forgepack.security.internal.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

/**
 * Configuration properties for <strong>additional</strong> public (permit-all) endpoint patterns
 * defined by the consuming project.
 *
 * <p>Configurable via {@code application.properties} under the
 * {@code forgepack.security.endpoints} prefix. All lists default to empty.</p>
 *
 * <p>These entries are <strong>additive</strong>: they are merged with the library's
 * built-in public endpoints at runtime. The built-in defaults are:</p>
 * <ul>
 *     <li>Any method: {@code /actuator/health}, {@code /actuator/info},
 *         {@code /api/v1/auth/**}, {@code /v3/api-docs/**}, {@code /swagger-ui/**}</li>
 *     <li>POST: {@code /auth/login}, {@code /user/**}</li>
 *     <li>PUT: {@code /auth/resetPassword}</li>
 * </ul>
 *
 * <p>Example — adding extra endpoints in the consuming project:</p>
 * <pre>{@code
 * forgepack.security.endpoints.permit-all=/public/**, /health/custom
 * forgepack.security.endpoints.permit-post=/api/register, /api/forgot-password
 * forgepack.security.endpoints.permit-put=/api/confirm-email
 * }</pre>
 *
 * @param permitAll  Extra URL patterns to allow for any HTTP method. Default: empty.
 * @param permitPost Extra URL patterns to allow for {@code POST} requests only. Default: empty.
 * @param permitPut  Extra URL patterns to allow for {@code PUT} requests only. Default: empty.
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 */
@ConfigurationProperties(prefix = "forgepack.security.endpoints")
public record PropertiesSecurityEndpoints(
        @DefaultValue List<String> permitAll,
        @DefaultValue List<String> permitPost,
        @DefaultValue List<String> permitPut
) {}
