package es.wasabiweb.jwt.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.extern.slf4j.Slf4j;

//Clase definicion de los filtros http
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

        private static final String APPLICATION_JSON_VALUE = "application/problem+json";
        private final AuthenticationManager authenticationManager;

        // Contructor de clase
        public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
                this.authenticationManager = authenticationManager;
        }

        // Intento de autentificacion. Autentificamos el usuario y creamos el Token con
        // el user y el password del usuario
        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
                        throws AuthenticationException {

                String username = request.getParameter("username");
                String password = request.getParameter("password");
                log.info("El nombre del usuario es: {}", username);
                log.info("La contraseña del usuario es: {}", password);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                username, password);

                return authenticationManager.authenticate(authenticationToken);

        }

        /*
         * Le decimos a Spring que pasa si la autentificación es correcta. En este caso
         * vamos a añadir el token a través del response.
         */
        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                        FilterChain chain, Authentication authentication) throws IOException, ServletException {
                User user = (User) authentication.getPrincipal();

                // Algoritmo que usamos para firmar el JWT
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                // Creamos lo tokens acceso y de refresco
                String access_token = JWT.create().withSubject(user.getUsername())
                                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                                .withIssuer(request.getRequestURL().toString())
                                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                                                .collect(Collectors.toList()))
                                .sign(algorithm);

                String refresh_token = JWT.create().withSubject(user.getUsername())
                                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                                .withIssuer(request.getRequestURL().toString()).sign(algorithm);

                /*
                 * response.setHeader("acces_token", access_token);
                 * response.setHeader("refresh_token", refresh_token);
                 */

                Map<String, String> tokens = new HashMap<>();
                tokens.put("acces_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
        }

}
