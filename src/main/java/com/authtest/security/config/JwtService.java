package com.authtest.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static SecretKeyGenerator keyGenerator;


    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);

    }


    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = exctractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims exctractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(keyGenerator.getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(keyGenerator.getKey().toString());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims,
                                UserDetails userDetails){

        Date creationDate = new Date(System.currentTimeMillis());


        return Jwts.builder()
                .claims().add(extraClaims).and()
                .subject(userDetails.getUsername())
                .issuedAt(creationDate)
                .expiration(generateExpirationDate(creationDate))
                .signWith(getSignInKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    private Date generateExpirationDate(Date creationDate) {
        Long expirationMinutes = 10L;
        creationDate.setTime(creationDate.getTime() + (1000L * 60L * expirationMinutes));
        return creationDate;
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);

    }


}
