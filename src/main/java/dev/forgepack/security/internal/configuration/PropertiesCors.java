package dev.forgepack.security.internal.configuration;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Configuration properties for CORS (Cross-Origin Resource Sharing).
 *
 * <p>Configurable via {@code application.properties} under the {@code forgepack.cors}
 * prefix. All fields have sensible defaults and may be omitted by the consumer.</p>
 *
 * <p><strong>Note:</strong> when {@code allowCredentials} is {@code true} (the default),
 * the CORS spec forbids wildcard {@code *} for {@code allowedHeaders}. The default
 * value lists only the most common headers explicitly to comply with this rule.</p>
 *
 * @param allowedOrigins   Origin patterns allowed to access the API. Default: {@code http://localhost:5173}.
 * @param allowedMethods   HTTP methods allowed in cross-origin requests.
 *                         Default: {@code GET, POST, PUT, PATCH, DELETE, OPTIONS}.
 * @param allowedHeaders   Headers allowed in cross-origin requests.
 *                         Default: {@code Authorization, Content-Type, Accept, X-Requested-With}.
 * @param allowCredentials Whether credentials (cookies, authorization headers) are allowed. Default: {@code true}.
 * @param maxAge           Pre-flight response cache duration in seconds. Default: {@code 3600}.
 *
 * @author Marcelo Ribeiro Gadelha
 * @since 1.0
 */
@Validated
@ConfigurationProperties(prefix = "forgepack.cors")
public record PropertiesCors(
        @NotEmpty @DefaultValue("http://localhost:5173")                                             List<String> allowedOrigins,
        @NotEmpty @DefaultValue({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})               List<String> allowedMethods,
        @NotEmpty @DefaultValue({"Authorization", "Content-Type", "Accept", "X-Requested-With"})   List<String> allowedHeaders,
                  @DefaultValue("true")                                                              boolean      allowCredentials,
          @Min(0) @DefaultValue("3600")                                                              long         maxAge
) {}