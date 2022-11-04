package com.deenn.supportportal.domain;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity @Builder
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Table(name = "users")
public class User extends Auditable<String> implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(nullable = false, updatable = false)
    private Long id;
    private String userId;
    private String firstName;
    private String lastName;
    private String username;
    private String email;
    private String password;
    private String profileImageUrl;
    private Date lastLoginDate;
    private Date lastLoginDisplayDate;
    private Date joinDate;
    private String role;
    private String[] authorities;
    private boolean isActive;
    private boolean isNotLocked;
}
