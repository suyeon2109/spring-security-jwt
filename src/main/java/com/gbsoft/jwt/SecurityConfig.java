package com.gbsoft.jwt;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final TokenProvider tokenProvider;
	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
	private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity, HandlerMappingIntrospector introspector) throws Exception {
		MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
		httpSecurity
			// token을 사용하는 방식이기 때문에 csrf disable
			.csrf(CsrfConfigurer::disable)
			.exceptionHandling(authenticationManager -> authenticationManager
				.authenticationEntryPoint(jwtAuthenticationEntryPoint)
				.accessDeniedHandler(jwtAccessDeniedHandler))

			// enable h2-console
			.headers()
			.frameOptions()
			.sameOrigin()

			// 세션을 사용하지 않기 때문에 STATELESS로 설정
			.and()
			.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

			// HttpServletRequest를 사용하는 요청들에 대한 접근제한 설정
			.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
						.requestMatchers(mvcMatcherBuilder.pattern("/authenticate")).permitAll() // 로그인 api
						.requestMatchers(mvcMatcherBuilder.pattern("/signup")).permitAll() // 회원가입 api
						.requestMatchers(mvcMatcherBuilder.pattern("/favicon.ico")).permitAll() // h2-console, favicon.ico 요청 인증 무시
						.requestMatchers(PathRequest.toH2Console()).permitAll()
						.anyRequest().authenticated() // 그 외 인증 없이 접근X
			)
			.apply(new JwtSecurityConfig(tokenProvider)); // JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig class 적용

		return httpSecurity.build();
	}

}
