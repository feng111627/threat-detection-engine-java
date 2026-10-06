package com.github.feng111627.threatdetectionenginejava.config;

import com.github.feng111627.threatdetectionenginejava.service.DetectionService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Spring Bean 装配。 */
@Configuration
public class ServiceConfig {

    @Bean
    public DetectionService detectionService() {
        return new DetectionService();
    }
}
