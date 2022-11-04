package com.deenn.supportportal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.File;
import java.util.List;

import static com.deenn.supportportal.constants.FileConstant.USER_FOLDER;

@SpringBootApplication
@EnableJpaAuditing
public class SupportPortalApplication {

    public static void main(String[] args) {

        SpringApplication.run(SupportPortalApplication.class, args);
        new File(USER_FOLDER).mkdirs();

    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
