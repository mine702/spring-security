package io.security.springsecuritymaster;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /**
     * basic formLogin()
    Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .defaultSuccessUrl("/", true)
                        .failureUrl("/failed")
                        .usernameParameter("userId")
                        .passwordParameter("passwd")
                        .successHandler((request, response, authentication) -> {
                            log.info("authentication = {}", authentication.getName());
                            response.sendRedirect("/home");
                        })
                        .failureHandler((request, response, exception) -> {
                            log.info("exception = {}", exception.getMessage());
                            response.sendRedirect("/login");
                        })
                        .permitAll()
                );

        return http.build();
    }
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .httpBasic(
                        basic -> basic.authenticationEntryPoint(
                                new CustomAuthenticationEntryPoint()
                        )
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user1);
    }
}
