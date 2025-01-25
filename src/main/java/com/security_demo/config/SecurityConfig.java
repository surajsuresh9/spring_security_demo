package com.security_demo.config;

import com.security_demo.jwt.AuthEntryPointJwt;
import com.security_demo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private DataSource h2DataSource;

    @Autowired
    private AuthEntryPointJwt authEntryPointJwt;

    @Bean
    AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // disable cors filter
        http.csrf(AbstractHttpConfigurer::disable);

        // authorize requests
        http.authorizeHttpRequests(
                (requests) ->
                        requests.requestMatchers("/h2-console/**").permitAll()
                                .requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated());

        // make http session stateless
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //  enable login/ logout form
        //        http.formLogin(withDefaults());

        // enable http basic (Postman no redirect from login page) : no login/ logout form
        http.httpBasic(withDefaults());

        // enable this for h2 console to work
        http.headers(headers ->
                headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        // add auth filter for jwt
        // add authTokenFilter before UsernamePasswordAuthenticationFilter filter
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        // enable exception handling for auth filter failures/ errors
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPointJwt));
        return http.build();
    }

    // InMemoryUserDetailsManager || JdbcUserDetailsManager
    @Bean
    public UserDetailsService userDetailsService() {
        return new JdbcUserDetailsManager(h2DataSource);
    }

    @Bean
    CommandLineRunner commandLineRunner() {
        return args -> {
            UserDetails user1 = User.withUsername("john").password(passwordEncoder().encode("123455")).roles("user").build();
            UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("admin")).roles("admin").build();

            JdbcUserDetailsManager manager = new JdbcUserDetailsManager(h2DataSource);
            manager.createUser(user1);
            manager.createUser(admin);
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}