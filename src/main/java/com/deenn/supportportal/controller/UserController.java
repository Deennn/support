package com.deenn.supportportal.controller;

import com.deenn.supportportal.domain.User;
import com.deenn.supportportal.dto.LoginDto;
import com.deenn.supportportal.dto.UserDto;
import com.deenn.supportportal.exception.*;
import com.deenn.supportportal.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static com.deenn.supportportal.constants.FileConstant.*;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

@RestController @RequiredArgsConstructor
@RequestMapping(path = { "/","/user"})
public class UserController extends ExceptionHandling {

    private final UserService userService;




    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody LoginDto loginDto) {
        HttpHeaders jwtHeaders = userService.login(loginDto);
        User loginUser = userService.getUserByUsername(loginDto.getUsername());
        return new ResponseEntity<>(loginUser, jwtHeaders, OK);
    }


    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody UserDto userDto) throws EmailAlreadyExistsException, UserNotFoundException, UsernameExistsException {
       User user = userService.register(userDto);
       return ResponseEntity.ok(user);
    }

    @PostMapping("/add")
    public ResponseEntity<User> addNewUser(@RequestParam String firstName,
                                           @RequestParam String lastName,
                                           @RequestParam String username,
                                           @RequestParam String email,
                                           @RequestParam String role,
                                           @RequestParam String isNotLocked,
                                           @RequestParam String password,
                                           @RequestParam String isActive,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException {
        UserDto userDto = UserDto.builder()
                .firstName(firstName)
                .lastName(lastName)
                .username(username)
                .email(email)
                .role(role)
                .password(password)
                .isNotLocked(Boolean.parseBoolean(isNotLocked))
                .isActive(Boolean.parseBoolean(isActive))
                .build();
        User newUser  = userService.addNewUser(userDto, profileImage);
        return ResponseEntity.ok(newUser);
    }

    @PostMapping("/update")
    public ResponseEntity<User> updateUser(@RequestParam String currentUsername,
                                           @RequestParam String firstName,
                                           @RequestParam String lastName,
                                           @RequestParam String username,
                                           @RequestParam String email,
                                           @RequestParam String role,
                                           @RequestParam String isNotLocked,
                                           @RequestParam String password,
                                           @RequestParam String isActive,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException {
        UserDto userDto = UserDto.builder()
                .firstName(firstName)
                .lastName(lastName)
                .username(username)
                .email(email)
                .role(role)
                .password(password)
                .isNotLocked(Boolean.parseBoolean(isNotLocked))
                .isActive(Boolean.parseBoolean(isActive))
                .build();
        User updateUser  = userService.updateUser(currentUsername,userDto, profileImage);
        return ResponseEntity.ok(updateUser);
    }

    @GetMapping("find/{username}")
    public ResponseEntity<User> getUser(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserByUsername(username));
    }


    @GetMapping("/users")
    public ResponseEntity<List<User>> getUser() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/resetPassword/{email}")
    public ResponseEntity<String> resetPassword(@PathVariable String email) throws EmailNotFoundException {
        String password = "12345";
        userService.resetPassword(email, password);

        return ResponseEntity.ok("An Email with a new password sent");
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<String> deleteUser(@PathVariable Long  id) {
        userService.deleteUser(id);
        return ResponseEntity.ok("User deleted successfully");
    }

    @PostMapping("/updateProfile")
    public ResponseEntity<User> updateProfileImage(@RequestParam String username, @RequestParam(value = "profileImage") MultipartFile profileImage) throws UserNotFoundException, EmailAlreadyExistsException, UsernameExistsException, IOException {
        return ResponseEntity.ok(userService.updateProfileImage(username, profileImage));
    }

    @GetMapping(path = "/image/profile/{username}", produces = IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable String username) throws IOException {
        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + username);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (InputStream inputStream = url.openStream()) {
            int bytesRead;
            byte[] chunk = new byte[1024];
            while((bytesRead = inputStream.read(chunk)) > 0) {
                byteArrayOutputStream.write(chunk, 0, bytesRead);
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    @GetMapping(path = "/image/{username}/{fileName}", produces = IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(@PathVariable String username, @PathVariable String fileName) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName));
    }



}
