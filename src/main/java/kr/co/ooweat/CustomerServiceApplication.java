package kr.co.ooweat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Collections;

@EnableScheduling    //스케쥴 기능 활성화
@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class CustomerServiceApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(CustomerServiceApplication.class);
        app.setDefaultProperties(Collections
                .singletonMap("server.port", "${server.port}"));
        app.run(args);
    }
}
