package com.authtest.security.auth;

import com.authtest.security.error.ErrorResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.InvalidParameterException;
import java.time.Instant;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request){
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(service.register(request));
        }catch (InvalidParameterException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponse.builder()
                                                                                    .status(HttpStatus.BAD_REQUEST.value())
                                                                                    .message(e.getMessage())
                                                                                    .date(Instant.now())
                                                                                    .build());
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request){
        try {
            return ResponseEntity.status(HttpStatus.OK).body(service.authenticate(request));
        }catch (InvalidParameterException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponse.builder()
                                                                                        .status(HttpStatus.BAD_REQUEST.value())
                                                                                        .message(e.getMessage())
                                                                                        .date(Instant.now())
                                                                                        .build());
        }
    }

}
