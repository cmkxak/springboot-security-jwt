package com.study.inflearnsecurity.config;

import com.study.inflearnsecurity.jwt.JwtAccessDeniedHandler;
import com.study.inflearnsecurity.jwt.JwtAuthenticationEntryPoint;
import com.study.inflearnsecurity.jwt.JwtTokenFIlter;
import com.study.inflearnsecurity.jwt.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            JwtTokenProvider jwtTokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring()
                .antMatchers("/h2-console/**",
                        "/favicon.ico", "/error");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf().disable()
                //인증 과정, 권한 확인 과정에서 발생하는 예외 처리
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                //h2-console이 가능하도록 함.
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()

                //HttpServletRequest를 사용하는 요청들에 대한 접근 제한을 설정하겠다는 의미
                .authorizeRequests()
                .antMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll()
                .anyRequest().authenticated() //나머지 요청은 인증 받아야 된다.

                //세션을 사용하지 않으므로 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                //UsernamePasswordAuthenticationFilter 전에 JwtTokenFIlter를 수행하겠다는 의미.
                .addFilterBefore(new JwtTokenFIlter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
