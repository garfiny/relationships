package com.garfiny.relationships.infrastructure.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportResource;

@Configuration
@ComponentScan("com.garfiny.relationships")
@ImportResource("classpath:spring/root-context.xml")

@Import(MvcConfig.class)
public class ApplicationConfig {

}
