package com.example.jwt.config;

import com.example.jwt.filter.DomainWhitelistFilter;
import com.example.jwt.filter.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final DomainWhitelistFilter domainWhitelistFilter;
    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(DomainWhitelistFilter domainWhitelistFilter,
                          JwtAuthFilter jwtAuthFilter) {
        this.domainWhitelistFilter = domainWhitelistFilter;
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/verify").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(domainWhitelistFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
