package com.deenn.supportportal.dto;

import com.deenn.supportportal.enumeration.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.EnumType;
import javax.persistence.Enumerated;

@AllArgsConstructor @Getter @Setter
@Builder
public class UserDto {

    private String firstName;
    private String lastName;
    private String username;
    private String email;
    private String password;
    private String profileImageUrl;

    private String role;
    private boolean isActive;
    private boolean isNotLocked;
}
