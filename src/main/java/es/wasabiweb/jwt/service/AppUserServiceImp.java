package es.wasabiweb.jwt.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import es.wasabiweb.jwt.model.AppUser;
import es.wasabiweb.jwt.model.Role;
import es.wasabiweb.jwt.repo.AppUserRepo;
import es.wasabiweb.jwt.repo.RoleRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImp implements AppUserService {

	private final AppUserRepo appUserRepo;
	private final RoleRepo roleRepo;

	@Override
	public AppUser saveAppUser(AppUser appUser) {
		log.info("Saving new user to the database: " + appUser.getName());
		return appUserRepo.save(appUser);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving new role {} to the database", role.getName());
		return roleRepo.save(role);
	}

	@Override
	public void addRoleToAppUser(String username, String roleName) {
		log.info("Saving new role {} to user {}", username, roleName);
		AppUser appUser = appUserRepo.findByUsername(username);
		Role role = roleRepo.findByName(roleName);
		appUser.getRoles().add(role);

	}

	@Override
	public AppUser getAppUser(String username) {
		log.info("Fetching user {}", username);
		return appUserRepo.findByUsername(username);
	}

	@Override
	public List<AppUser> getAppUsers() {
		log.info("Fetching all users");
		return appUserRepo.findAll();
	}

}
