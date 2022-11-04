package com.deenn.supportportal.service;

import com.deenn.supportportal.domain.User;
import com.deenn.supportportal.domain.UserPrincipal;
import com.deenn.supportportal.dto.LoginDto;
import com.deenn.supportportal.dto.UserDto;
import com.deenn.supportportal.exception.EmailAlreadyExistsException;
import com.deenn.supportportal.exception.EmailNotFoundException;
import com.deenn.supportportal.exception.UserNotFoundException;
import com.deenn.supportportal.exception.UsernameExistsException;
import org.springframework.http.HttpHeaders;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface UserService {

    HttpHeaders login(LoginDto loginDto);



    User register(UserDto userDto) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException;

    List<User> getAllUsers();

    User getUserByUsername(String username);

    User getUserByEmail(String email);

    User addNewUser(UserDto userDto, MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException;

    User updateUser(String currentUsername,UserDto userDto, MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException;

    void deleteUser(long id);

    void resetPassword(String password, String email) throws EmailNotFoundException;

    User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException;
}
