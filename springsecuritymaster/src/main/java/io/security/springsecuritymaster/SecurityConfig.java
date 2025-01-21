package io.security.springsecuritymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

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

    /**
     * rememberMe()
     *
     * @Bean public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
     * http
     * .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
     * .formLogin(Customizer.withDefaults())
     * .rememberMe(remeberMe -> remeberMe
     * .alwaysRemember(true)
     * .tokenValiditySeconds(3600)
     * .userDetailsService(userDetailsService())
     * .rememberMeParameter("remember")
     * .rememberMeCookieName("remember")
     * .key("security")
     * );
     * <p>
     * return http.build();
     * }
     */

    /**
     * anonymous()
     *
     * @Bean public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
     * http
     * .authorizeHttpRequests(auth -> auth
     * .requestMatchers("/anonymous").hasRole("GUEST")
     * .requestMatchers("/anonymousContext", "/authentication").permitAll()
     * .anyRequest()
     * .authenticated())
     * .formLogin(Customizer.withDefaults())
     * .anonymous(anonymous -> anonymous
     * .principal("guest")
     * .authorities("ROLE_GUEST")
     * )
     * ;
     * return http.build();
     * }
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/logoutSuccess").permitAll()
                        .anyRequest()
                        .authenticated())
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutUrl("/logoutProc")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc", "POST"))
                        .logoutSuccessUrl("/logoutSuccess")
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/logoutSuccess");
                            }
                        })
                        .invalidateHttpSession(true)
                        .deleteCookies("rememberMe", "JSESSIONID")
                        .clearAuthentication(true)
                        .addLogoutHandler(new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession session = request.getSession();
                                session.invalidate();
                                SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
                                SecurityContextHolder.getContextHolderStrategy().clearContext();
                            }
                        })
                        .permitAll()
                )
        ;
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user1);
    }
}
