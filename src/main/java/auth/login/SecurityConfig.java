package auth.login;



import auth.login.실습3.CustomOAuth2UserService;
import auth.login.실습3.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private auth.login.실습3.JwtFilter jwtFilter;
    private CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(JwtFilter jwtFilter, CustomOAuth2UserService customOAuth2UserService) {
        this.jwtFilter = jwtFilter;
        this.customOAuth2UserService = customOAuth2UserService;
    }


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() { // security를 적용하지 않을 리소스
        return web -> web.ignoring()
                .requestMatchers("/error", "/favicon.ico");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests((authorize) -> {
                    authorize.requestMatchers("/api/user/signin", "/api/user/signup").permitAll();
                    authorize.anyRequest().authenticated();
                })

                .oauth2Login(oauth -> oauth.userInfoEndpoint(c -> c.userService(customOAuth2UserService)))

                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)


                .sessionManagement((session) -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                });

        return http.build();
    }
}
