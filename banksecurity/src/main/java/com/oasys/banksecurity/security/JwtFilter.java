package com.oasys.banksecurity.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.oasys.banksecurity.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
@Component
public class JwtFilter extends OncePerRequestFilter{
@Autowired 
JwtService jwtser;
@Autowired
UserInfoUserDetailsService userinfoser;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authHeader= request.getHeader("Authorization");
		String token=null;
		String username=null;
		if(authHeader != null && authHeader.startsWith("Bearer ")) {
			token=authHeader.substring(7);
			username=jwtser.extractUserName(token);
		}
		if(username !=null && SecurityContextHolder.getContext().getAuthentication()==null) {
		UserDetails userdetails=userinfoser.loadUserByUsername(username);
		if(jwtser.validateToken(token, userdetails)) {
			UsernamePasswordAuthenticationToken gettoken=new UsernamePasswordAuthenticationToken(username,null, userdetails.getAuthorities());
			gettoken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(gettoken);
		}
			
		}
		filterChain.doFilter(request, response);
	}

}
