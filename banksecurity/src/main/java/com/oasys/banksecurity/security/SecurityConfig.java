package com.oasys.banksecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Autowired JwtFilter filters;

	@Bean
	UserDetailsService UserDetailService() {
		return new UserInfoUserDetailsService();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		  return http.csrf(csrf -> csrf.disable())
		            .authorizeHttpRequests(auth -> {
		                auth.requestMatchers("/bank/insertuser","/bank/getmsg","/bank/authenticate").permitAll();
		                auth.requestMatchers("/bank/getuser","bank/getbyid/{id}","/bank/newaccount").hasAnyRole("USER", "ADMIN");
		                auth.requestMatchers("/bank/getall","bank/getbyid/{id}").hasAnyRole("ADMIN");
		            })
		            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
		            .authenticationProvider(authenticationProvider()).addFilterAt(filters, UsernamePasswordAuthenticationFilter.class).build();
	}

	@Bean
	AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAutheticate = new DaoAuthenticationProvider();
		daoAutheticate.setUserDetailsService(UserDetailService());
		daoAutheticate.setPasswordEncoder(passwordEncoder());
		return daoAutheticate;
	}
	@Bean
	public AuthenticationManager authManager(AuthenticationConfiguration authconfig) throws Exception {
		return authconfig.getAuthenticationManager();
		
	}
}
