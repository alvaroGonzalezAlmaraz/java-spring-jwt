package es.wasabiweb.jwt.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import es.wasabiweb.jwt.model.AppUser;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {

    AppUser findByUsername(String username);
}
