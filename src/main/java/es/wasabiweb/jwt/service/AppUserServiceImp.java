package es.wasabiweb.jwt.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.slf4j.Logger;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
public class AppUserServiceImp implements AppUserService, UserDetailsService {

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

	// Este método se sobre escribe para darle a Spring los detalles de los uroles
	// de los usuarios??
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = appUserRepo.findByUsername(username);
		if (appUser == null) {
			log.error("Usuario no encontrado en la base de datos");
			throw new UsernameNotFoundException("Usuario no encontrado en la base de datos");
		} else {
			log.error("Usuario encontrado en la base de datos: {}", username);

		}

		// Nos tiene que devolver un usuario de Spring Security
		//Creamos un arraylist para sacar los roles del usuario
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

		//Lo llenamos
		appUser.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()))
		});

		return new org.springframework.security.core.userdetails.User(appUser.getName(), appUser.getPassword(),
				authorities);
	}

}
