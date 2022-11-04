package com.deenn.supportportal.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter @Builder
@AllArgsConstructor
public class LoginDto {

    private String username;
    private String password;
}
