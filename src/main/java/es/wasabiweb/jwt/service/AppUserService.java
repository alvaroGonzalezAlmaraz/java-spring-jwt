package es.wasabiweb.jwt.service;

import java.util.List;
import es.wasabiweb.jwt.model.AppUser;
import es.wasabiweb.jwt.model.Role;

public interface AppUserService {
    AppUser saveAppUser(AppUser user);

    Role saveRole(Role role);

    void addRoleToAppUser(String username, String roleName);

    AppUser getAppUser(String username);

    List<AppUser> getAppUsers();
}
