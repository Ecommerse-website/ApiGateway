package com.ApiGateway.util;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {

	public static final String SECRET ="5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";
	
	public void validateToken(final String token) {
		Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token);
	}

	private Key getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	public String extractUsername(final String token) {
		return extractClaim(token, Claims::getSubject);
		
	}
	
	public Date extractExpirationDate(final String token) {
		return extractClaim(token, Claims::getExpiration);
		
	}
	
	public <T> T extractClaim(final String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
		
	}
	
	public Claims extractAllClaims(final String token) {
		return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJwt(token).getBody();
		
	}
}
