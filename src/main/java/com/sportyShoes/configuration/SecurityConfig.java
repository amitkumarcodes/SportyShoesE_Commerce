package com.sportyShoes.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.sportyShoes.service.CustomUserDetailService;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


@EnableWebSecurity
@Configuration
public class SecurityConfig{
	@Autowired
	GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler;
	
	@Autowired
	CustomUserDetailService customUserDetailService;
	
	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception{
		http
	        .authorizeHttpRequests((requests) -> requests
	            .requestMatchers("/", "/shop/**", "/register", "/h2-console/**", "/login", "/admin/products/add").permitAll()
	            .requestMatchers("/admin/**").hasRole("ADMIN")
	            .anyRequest().authenticated())
	        .formLogin(login -> login
	            .loginPage("/login")
	            .permitAll()
	            .failureUrl("/login?error=true")
	            .defaultSuccessUrl("/", true)
	            .usernameParameter("email")
	            .passwordParameter("password"))
	        .oauth2Login(oauth2 -> oauth2
	            .loginPage("/login")
	            .successHandler(googleOAuth2SuccessHandler))
	        .logout(logout -> logout
	            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	            .logoutSuccessUrl("/login")
	            .invalidateHttpSession(true)
	            .deleteCookies("JSESSIONID"))
	        .exceptionHandling(e -> {})
	        .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
	        .headers(headers -> headers.frameOptions().sameOrigin());
		
    return http.build();
	
	}
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		auth.userDetailsService(customUserDetailService);
	}
	
	
	
	@Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/resources/**", "/static/**", "/images/**", "/productimages/**", "/css/**", "/js/**");
    }
	
	
}
