package demo;

// Test fixture for semgrep/java-spring.yml. Never compiled or run.

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfigs {

    @Bean
    SecurityFilterChain sessionApp(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // expect: spring-permitall-sensitive-path
                .requestMatchers("/admin/**").permitAll()
                // expect: spring-permitall-sensitive-path
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/css/**", "/login").permitAll()
                .anyRequest().authenticated())
            .formLogin(f -> f.loginPage("/login"));
        // expect: spring-csrf-disabled-with-session
        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    SecurityFilterChain legacyApp(HttpSecurity http) throws Exception {
        // expect: spring-csrf-disabled-with-session
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            // expect: spring-permitall-sensitive-path
            .anyRequest().permitAll();
        return http.build();
    }

    @Bean
    SecurityFilterChain statelessApi(HttpSecurity http) throws Exception {
        http
            .csrf(c -> c.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}
