package com.garfiny.relationships.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import com.garfiny.relationships.infrastructure.config.annotation.Dev;
import com.garfiny.relationships.infrastructure.config.annotation.Embedded;
import com.garfiny.relationships.infrastructure.config.annotation.Production;

@Configuration
@ComponentScan("com.garfiny.relationships")
public class ApplicationConfig {

	@Configuration
	@Embedded
	@PropertySource("classpath:embedded/application.properties")
	static class EmbeddedApplicationConfig {
		@Bean
		public PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {
			PropertySourcesPlaceholderConfigurer propertyPlaceholder = new PropertySourcesPlaceholderConfigurer();
	        Resource[] resourceLocations = new Resource[] {
	                new ClassPathResource("development/application.properties")
	        };
	        propertyPlaceholder.setLocations(resourceLocations);
	        return propertyPlaceholder;
	    }
	}
	
	@Dev
	@Configuration
	static class DevelopmentApplicationConfig {
		
		@Bean
		public PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {
			PropertySourcesPlaceholderConfigurer propertyPlaceholder = new PropertySourcesPlaceholderConfigurer();
	        Resource[] resourceLocations = new Resource[] {
	                new ClassPathResource("development/application.properties")
	        };
	        propertyPlaceholder.setLocations(resourceLocations);
	        System.out.println("==================== ${default_login_success_url}====================");
	        return propertyPlaceholder;
	    }
	}
	
	@Configuration
	@Production
	static class ProductionApplicationConfig {
		@Bean
		public PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {
			PropertySourcesPlaceholderConfigurer propertyPlaceholder = new PropertySourcesPlaceholderConfigurer();
	        Resource[] resourceLocations = new Resource[] {
	                new ClassPathResource("development/application.properties")
	        };
	        propertyPlaceholder.setLocations(resourceLocations);
	        System.out.println("====================${default_login_success_url}====================");
	        return propertyPlaceholder;
	    }
	}
	
}
