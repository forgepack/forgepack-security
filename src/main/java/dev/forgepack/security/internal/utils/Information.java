package dev.forgepack.security.internal.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class Information {

    private static final Logger log = LoggerFactory.getLogger(Information.class);

    public static Optional<String> getCurrentUser() {
        try {
            return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                    .map(auth -> {
                        Object principal = auth.getPrincipal();
                        if (principal instanceof UserDetails userDetails) {
                            String username = userDetails.getUsername();
                            log.info("Current authenticated user: {}", username);
                            return username;
                        }
                        return principal.toString();
                    });
        } catch (Exception e) {
            log.error("Error getting current user: ", e);
            return Optional.empty();
        }
    }
}
