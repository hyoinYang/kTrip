package Iniro.kTrip.config;

import Iniro.kTrip.handler.OAuth2SuccessHandler;
import lombok.RequiredArgsConstructor;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final DefaultOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http    .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/", "/login", "/join", "/login/*", "/signUp", "/signIn").permitAll()
                        .anyRequest().authenticated()
                )
//                .formLogin(form -> form
//                        .loginPage("/login")
//                        .defaultSuccessUrl("/", true)
//                        .permitAll()
//                )

                .logout(logout -> logout
                        .permitAll())

                .oauth2Login(oauth2 -> oauth2
                        .redirectionEndpoint(endpoint -> endpoint.baseUri("/"))
                                .userInfoEndpoint(endpoint -> endpoint.userService(oAuth2UserService)
                                )
                                .successHandler(oAuth2SuccessHandler)
                                //.defaultSuccessUrl("/", true)
                                //.failureUrl("/login?error=true")


                // oauth2 설정
//                .oauth2Login(oauth -> // OAuth2 로그인 기능에 대한 여러 설정의 진입점
//                // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정을 담당
//                    oauth.userInfoEndpoint(c -> c.userService(oAuthService))
//                        // 로그인 성공 시 핸들러
//                        .successHandler(OAuthSuccessHandler)
        );

        return http.build();

    }

}