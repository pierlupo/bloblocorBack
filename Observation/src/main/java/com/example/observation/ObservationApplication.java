package com.example.observation;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@SpringBootApplication
@EnableMongoRepositories
public class ObservationApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(ObservationApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {

    }
}
