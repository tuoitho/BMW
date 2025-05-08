package com.cosmeticsellingwebsite.config;

import com.cosmeticsellingwebsite.util.OutputEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
    /**
     * Add the OutputEncoder utility to Thymeleaf context
     */
    @Bean
    public OutputEncoder outputEncoder() {
        return new OutputEncoder();
    }
    
    /**
     * Configure resource handlers with Subresource Integrity (SRI) support
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/");
    }
}