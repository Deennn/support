package com.deenn.supportportal.service.Impl;

import com.deenn.supportportal.domain.User;
import com.deenn.supportportal.domain.UserPrincipal;
import com.deenn.supportportal.dto.LoginDto;
import com.deenn.supportportal.dto.UserDto;
import com.deenn.supportportal.enumeration.Role;
import com.deenn.supportportal.exception.EmailAlreadyExistsException;
import com.deenn.supportportal.exception.EmailNotFoundException;
import com.deenn.supportportal.exception.UserNotFoundException;
import com.deenn.supportportal.exception.UsernameExistsException;
import com.deenn.supportportal.repository.UserRepository;
import com.deenn.supportportal.service.EmailService;
import com.deenn.supportportal.service.LoginAttemptService;
import com.deenn.supportportal.service.UserService;
import com.deenn.supportportal.utils.JwtTokenProvider;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.mail.MessagingException;
import javax.transaction.Transactional;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.deenn.supportportal.constants.FileConstant.*;
import static com.deenn.supportportal.constants.SecurityConstants.JWT_TOKEN_HEADER;
import static com.deenn.supportportal.constants.UserConstant.*;
import static com.deenn.supportportal.enumeration.Role.ROLE_USER;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.apache.commons.lang3.StringUtils.EMPTY;


@Service @Transactional
@Qualifier("UserDetailsService")
public class UserServiceImpl implements UserService, UserDetailsService {

    private final Logger LOGGER = LoggerFactory.getLogger(getClass());
    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final LoginAttemptService loginAttemptService;

    private final EmailService emailService;

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;


    ExecutorService executorService = Executors.newSingleThreadExecutor();

    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, LoginAttemptService loginAttemptService, EmailService emailService, @Lazy AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.loginAttemptService = loginAttemptService;
        this.emailService = emailService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User users = userRepository.findUsersByUsername(username);
        if (users == null) {
            LOGGER.error("user with username " + username + " not found");
            throw new UsernameNotFoundException("user with username " + username + " not found");

        } else {
            validateLoginAttempt(users);
            users.setLastLoginDisplayDate(users.getLastLoginDate());
            users.setLastLoginDate(new Date());
            userRepository.save(users);
            UserPrincipal userPrincipal = new UserPrincipal(users);
            LOGGER.info("Returning found user with username " + username);
            return userPrincipal;
        }

    }

    private void validateLoginAttempt(User users) {
        if (users.isNotLocked()) {
            users.setNotLocked(!loginAttemptService.hasExceededMaxAttempts(users.getUsername()));

        } else {
            loginAttemptService.evictUserFromLoginAttemptCache(users.getUsername());
        }
    }

    @Override
    public HttpHeaders login(LoginDto loginDto) {
        authenticate(loginDto.getUsername(), loginDto.getPassword());
        User loginUser = getUserByUsername(loginDto.getUsername());
        UserPrincipal userPrincipal =  new UserPrincipal(loginUser);
        return getJwtHeader(userPrincipal);
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return httpHeaders;
    }
    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }

    @Override
    public User register(UserDto userDto) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException {
        validateUsernameAndEmail(EMPTY, userDto.getUsername(), userDto.getEmail());
        
        User user = User.builder()
                .userId(generateUserId())
                .firstName(userDto.getFirstName())
                .lastName(userDto.getLastName())
                .username(userDto.getUsername().toLowerCase())
                .email(userDto.getEmail())
                .joinDate(new Date())
                .password(bCryptPasswordEncoder.encode(userDto.getPassword()))
                .isActive(true)
                .isNotLocked(true)
                .role(ROLE_USER.name())
                .authorities(ROLE_USER.getAuthorities())
                .profileImageUrl(getTemporaryProfileImageUrl(userDto.getUsername()))
                .build();
        executorService.execute( () -> {
            try {
                emailService.sendEmail(userDto.getFirstName(), userDto.getEmail());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
        });
        return userRepository.save(user);
    }


    @Override
    public User addNewUser(UserDto userDto, MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException {
        validateUsernameAndEmail(EMPTY, userDto.getUsername(), userDto.getEmail());
        User user = User.builder()
                .userId(generateUserId())
                .firstName(userDto.getFirstName())
                .lastName(userDto.getLastName())
                .username(userDto.getUsername().toLowerCase())
                .email(userDto.getEmail())
                .joinDate(new Date())
                .password(bCryptPasswordEncoder.encode(userDto.getPassword()))
                .isActive(userDto.isActive())
                .isNotLocked(userDto.isNotLocked())
                .role((getRoleEnumName(userDto.getRole()).name()))
                .authorities((getRoleEnumName(userDto.getRole()).getAuthorities()))
                .profileImageUrl(setProfileImageUrl(userDto.getUsername()))
                .build();
        executorService.execute( () -> {
            try {
                emailService.sendEmail(userDto.getFirstName(), userDto.getEmail());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
        });
        saveProfileImage(user,profileImage);
        return userRepository.save(user);
    }

    private void saveProfileImage(User user, MultipartFile profileImage) throws IOException {
        if (profileImage != null) {
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();
            if (!Files.exists(userFolder)) {
                Files.createDirectories(userFolder);
                LOGGER.info(DIRECTORY_CREATED + userFolder);
            }
            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(profileImage.getInputStream(), userFolder.resolve(user.getUsername() +DOT + JPG_EXTENSION), REPLACE_EXISTING);
            user.setProfileImageUrl(setProfileImageUrl(user.getUsername()));
            LOGGER.info(FILE_SAVED_IN_FILE_SYSTEM + profileImage.getOriginalFilename());
        }
    }
    private String setProfileImageUrl(String username) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(USER_IMAGE_PATH + username + FORWARD_SLASH + username + DOT + JPG_EXTENSION).toUriString();
    }
    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase());
    }

    @Override
    public User updateUser(String currentUsername, UserDto userDto, MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException {
        User currentUser = validateUsernameAndEmail(currentUsername, userDto.getUsername(), userDto.getEmail());
        assert currentUser != null;
        currentUser.setUsername(userDto.getUsername());
        currentUser.setFirstName(userDto.getFirstName());
        currentUser.setLastName(userDto.getLastName());
        currentUser.setEmail(userDto.getEmail());
        currentUser.setActive(userDto.isActive());
        currentUser.setNotLocked(userDto.isNotLocked());
        currentUser.setRole(getRoleEnumName(userDto.getRole()).name());
        currentUser.setAuthorities(getRoleEnumName(userDto.getRole()).getAuthorities());
        executorService.execute( () -> {
            try {
                emailService.sendEmail(userDto.getFirstName(), userDto.getEmail());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
        });
        userRepository.save(currentUser);
        saveProfileImage(currentUser, profileImage);
        return currentUser;

    }

    @Override
    public void deleteUser(long id) {
        userRepository.deleteById(id);

    }

    @Override
    public void resetPassword(String email, String password) throws EmailNotFoundException {
        User user = userRepository.findUsersByEmail(email);
        if (user == null) {
            throw new EmailNotFoundException(NO_USER_FOUND_BY_USERNAME + email);
        }

        user.setPassword(bCryptPasswordEncoder.encode(password));
        userRepository.save(user);
        executorService.execute( () -> {
            try {
                emailService.sendEmail(user.getFirstName(), user.getEmail());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException {
        User user = validateUsernameAndEmail(username, null, null);
        saveProfileImage(user, profileImage);
        return null;
    }



    private String getTemporaryProfileImageUrl(String username) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(DEFAULT_USER_IMAGE_PATH + username.toLowerCase()).toUriString();
    }

    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }

    private User validateUsernameAndEmail(String currentUsername, String newUsername, String newEmail) throws UserNotFoundException, UsernameExistsException, EmailAlreadyExistsException {

        User userByNewUsername = getUserByUsername(newUsername);
        User userByNewEmail = getUserByEmail(newEmail);

        if (StringUtils.isNoneEmpty(currentUsername)) {
            User currentUser = getUserByUsername(currentUsername);
            if (currentUser == null) {
                throw new UserNotFoundException(NO_USER_FOUND_BY_USERNAME + currentUsername);
            }

            if (userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())) {
                throw new UsernameExistsException(USERNAME_ALREADY_EXISTS);
            }

            if (userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())) {
                throw new EmailAlreadyExistsException(EMAIL_ALREADY_EXISTS);
            }
            return currentUser;

        } else {

            if (userByNewUsername != null) {
                throw new UsernameExistsException(USERNAME_ALREADY_EXISTS);
            }


            if (userByNewEmail != null ) {
                throw new EmailAlreadyExistsException(EMAIL_ALREADY_EXISTS);
            }
            return null;
        }

    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public User getUserByUsername(String username) {
        return userRepository.findUsersByUsername(username);
    }

    @Override
    public User getUserByEmail(String email) {
        return userRepository.findUsersByEmail(email);
    }

}
