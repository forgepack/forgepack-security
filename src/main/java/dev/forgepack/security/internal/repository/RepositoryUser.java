package dev.forgepack.security.internal.repository;

import dev.forgepack.security.internal.model.User;
import dev.forgepack.core.api.repository.RepositoryCrud;
import org.springframework.data.jpa.repository.Query;
import java.util.Optional;
import java.util.UUID;

public interface RepositoryUser extends RepositoryCrud<User> {

    @Query("SELECT DISTINCT u FROM User u LEFT JOIN FETCH u.role r LEFT JOIN FETCH r.privilege WHERE u.username = :name")
    Optional<User> findByUsername(String name);
    boolean existsByUsernameIgnoreCase(String name);
    boolean existsByUsernameIgnoreCaseAndIdNot(String name, UUID id);
    boolean existsByEmailIgnoreCase(String name);
    boolean existsByEmailIgnoreCaseAndIdNot(String name, UUID id);
}
