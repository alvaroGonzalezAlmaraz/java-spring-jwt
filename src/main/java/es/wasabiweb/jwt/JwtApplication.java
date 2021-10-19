package es.wasabiweb.jwt;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import es.wasabiweb.jwt.model.AppUser;
import es.wasabiweb.jwt.model.Role;
import es.wasabiweb.jwt.service.AppUserService;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

	// Creamos un Bean PAsswordEncoder para que se cree y este disponible cuando
	// arranquemos la aplicación.
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// Command line runner, todo lo que este de aqui para abajo, se ejecuta cada vez
	// que ejecutemos la aplicación.
	@Bean
	CommandLineRunner run(AppUserService appUserService) {
		return args -> {
			appUserService.saveRole(new Role(null, "ROLE_USER"));
			appUserService.saveRole(new Role(null, "ROLE_MANAGER"));
			appUserService.saveRole(new Role(null, "ROLE_ADMIN"));
			appUserService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			appUserService.saveAppUser(new AppUser(null, "Pepe Lopez", "pepe", "1234", new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null, "Juan Lopez", "juan", "1234", new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null, "Jose Lopez", "jose", "1234", new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null, "Antonio Lopez", "antonio", "1234", new ArrayList<>()));

			appUserService.addRoleToAppUser("pepe", "ROLE_MANAGER");
			appUserService.addRoleToAppUser("pepe", "ROLE_ADMIN");
			appUserService.addRoleToAppUser("pepe", "ROLE_SUPER_ADMIN");
			appUserService.addRoleToAppUser("juan", "ROLE_ADMIN");
			appUserService.addRoleToAppUser("juan", "ROL_USER");
			appUserService.addRoleToAppUser("jose", "ROLE_USER");
			appUserService.addRoleToAppUser("pepe", "ROLE_USER");

		};
	}

}
