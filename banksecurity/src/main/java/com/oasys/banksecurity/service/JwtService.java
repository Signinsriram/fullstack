package com.oasys.banksecurity.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {

	private static final String SECRET = "iSzupJbetmVJ9HTdjp4EUUqsqDjXVymBnMsFatnWCl67jtNU4Iyfz0Zmt/Hpo8vypq9BrsE1LXeubbkFo3Y"
			+ "NcRXRPtG17Bso8AS+oGHU+uoMfXr0OI+zSf26xkS0k/wiWNkt7eHO7wGWA3xsw+eSRubD8+gAwoXalFFoIU8Qn4cWjZBGqJ8XSiOOeVztzgu"
			+ "P2to4k67SyzzYKVyvFj+TUi3Ad88sCwiyf3OAE4tkUEjCApd2/WPGHckenq5sw98fxy7b2p7g8VU7xzgGoSADYMY7viwl9fG0nW"
			+ "QxP24fdy6Gz+r48hHiBDBZWfNXT8RIprxl6Aa2nuoHVxNe0cyUhaznq6A6jj3lv1Idc31vC2Q";

	
	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}



	private Claims extractAllClaims(String token) {
		// TODO Auto-generated method stub\
		return Jwts.parser().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUserName(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}


	
	public String generatedToken(String username) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, username);
	}

	private static String createToken(Map<String, Object> claims, String username) {

		return Jwts.builder().setClaims(claims).setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 5))
				.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
	}

	private static Key getSignKey() {
		// TODO Auto-generated method stub
		byte[] token = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(token);
	}
}
