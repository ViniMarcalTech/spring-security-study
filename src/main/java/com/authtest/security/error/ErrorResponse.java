package com.authtest.security.error;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class ErrorResponse {
    private Integer status;
    private String message;
    private Instant date;
}
