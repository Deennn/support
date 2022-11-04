package com.deenn.supportportal.repository;

import com.deenn.supportportal.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    User findUsersByUsername(String username);
    User findUsersByEmail(String email);

}
