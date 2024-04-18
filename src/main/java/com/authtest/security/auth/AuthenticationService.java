package com.authtest.security.auth;

import com.authtest.security.config.JwtService;
import com.authtest.security.token.Token;
import com.authtest.security.token.TokenRepository;
import com.authtest.security.token.TokenType;
import com.authtest.security.user.Role;
import com.authtest.security.user.User;
import com.authtest.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.InvalidParameterException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {

        isAValidRegisterRequest(request);

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        var savedUser = repository.save(user);

        var jwtToken = jwtService.generateToken(user);

        saveUserToken(savedUser, jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        isAValidAuthenticationRequest(request);

        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidParameterException("Email is not registered!"));
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword())        );

        }catch (AuthenticationException e){
            throw new InvalidParameterException("Invalid Password!");
        }

        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken).build();
    }

    private void isAValidAuthenticationRequest(AuthenticationRequest request) {
        if (request.getEmail() == null || request.getPassword() == null){
            throw new InvalidParameterException("Is not a valid authentication request");
        }
    }

    private void isAValidRegisterRequest(RegisterRequest request) {
        if (request.getFirstname() == null || request.getLastname() == null|| request.getPassword() == null){
            throw new InvalidParameterException("Is not a valid register request");
        }
        if ( repository.findByEmail(request.getEmail()).isPresent()){
            throw new InvalidParameterException("Email is already in use!");
        }
    }

    private void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty()){
            return;
        }

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }
}
