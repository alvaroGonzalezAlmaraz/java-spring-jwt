package es.wasabiweb.jwt.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import es.wasabiweb.jwt.model.Role;

public interface RoleRepo extends JpaRepository<Role, Long> {

    Role findByName(String name);

}
