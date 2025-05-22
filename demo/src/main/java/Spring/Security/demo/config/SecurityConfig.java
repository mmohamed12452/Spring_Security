package Spring.Security.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // Define an in-memory user with ROLE_USER
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();

        // Define an in-memory admin with ROLE_ADMIN and ROLE_USER
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("adminpass")) // Admin password is 'adminpass'
                .roles("ADMIN", "USER") // Admin also has USER role to access user pages
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // 1. PUBLIC / PERMITTED ACCESS - ORDER IS CRUCIAL!
                        // These paths are accessible to everyone (authenticated or not).
                        // Ensure '/', '/welcome', '/login', and all static resources are listed.
                        .requestMatchers("/", "/welcome", "/login", "/css/**", "/js/**", "/images/**").permitAll()

                        // 2. AUTHORIZED ACCESS - ROLE-BASED
                        // Paths that require specific roles. More specific rules typically go before more general ones.
                        .requestMatchers("/admin/**").hasRole("ADMIN") // Only users with ROLE_ADMIN
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN") // Users with ROLE_USER or ROLE_ADMIN

                        // 3. ANY OTHER REQUEST - CATCH-ALL
                        // All other requests not explicitly defined above require authentication.
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login") // Specifies the URL of your custom login page
                        .defaultSuccessUrl("/welcome", true) // Redirect to /welcome after successful login (true forces redirection)
                        .permitAll() // Allows everyone to access the login page and its processing
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // The URL to trigger logout (typically a POST to /logout)
                        .logoutSuccessUrl("/welcome") // Redirects to /welcome after successful logout
                        .permitAll() // Allows everyone to perform logout
                )
                .csrf(csrf -> csrf.disable()); // IMPORTANT: Temporarily disable CSRF for easier testing during development.
        // FOR PRODUCTION, YOU MUST RE-ENABLE AND HANDLE CSRF TOKENS.
        // Thymeleaf's security dialect usually adds CSRF tokens automatically for forms.
        // If you still encounter issues, this is a good temporary debug step.

        return http.build();
    }
}