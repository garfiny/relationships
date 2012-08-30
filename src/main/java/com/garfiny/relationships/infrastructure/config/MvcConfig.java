package com.garfiny.relationships.infrastructure.config;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

@Configuration
@EnableWebMvc
@ComponentScan("com.garfiny.relationships.web.controllers")
public class MvcConfig extends WebMvcConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(MvcConfig.class);
	
//	@Inject
//	private Environment environment;

//	public void addResourceHandlers(ResourceHandlerRegistry registry) {
//		registry.addResourceHandler("/resources/**").addResourceLocations("/resources/**");
//	}
	
	@Bean
	public ViewResolver viewResolver() {
		logger.info("================================= loading view resolver============================");
		InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
		viewResolver.setSuffix(".jsp");
		viewResolver.setPrefix("/WEB-INF/views/");
		return viewResolver;
	}
	// implementing WebMvcConfigurer

//	public void addInterceptors(InterceptorRegistry registry) {
//		registry.addInterceptor(new AccountExposingHandlerInterceptor());
//		registry.addInterceptor(new DateTimeZoneHandlerInterceptor());
//		registry.addInterceptor(new UserLocationHandlerInterceptor());
//		registry.addInterceptor(new DeviceResolverHandlerInterceptor());
//	}
//
//	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
//		argumentResolvers.add(new AccountHandlerMethodArgumentResolver());
//		argumentResolvers.add(new DateTimeZoneHandlerMethodArgumentResolver());
//		argumentResolvers.add(new LocationHandlerMethodArgumentResolver());
//		argumentResolvers.add(new FacebookHandlerMethodArgumentResolver(environment.getProperty("facebook.appId"), environment.getProperty("facebook.appSecret")));
//		argumentResolvers.add(new DeviceHandlerMethodArgumentResolver());		
//	}
//
//	public void addResourceHandlers(ResourceHandlerRegistry registry) {
//		registry.addResourceHandler("/resources/**").addResourceLocations("/resources/");
//	}
//	
//	public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
//		converters.add(new MappingJacksonHttpMessageConverter());
//	}
//	
//	public Validator getValidator() {
//		LocalValidatorFactoryBean factory = new LocalValidatorFactoryBean();
//		ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
//		messageSource.setBasename("/WEB-INF/messages/validation");
//		if (environment.acceptsProfiles("embedded")) {
//			messageSource.setCacheSeconds(0);
//		}
//		factory.setValidationMessageSource(messageSource);
//		return factory;
//	}
//
//	// additional webmvc-related beans
//
//	/**
//	 * ViewResolver configuration required to work with Tiles2-based views.
//	 */
//	@Bean
//	public ViewResolver viewResolver() {
//		UrlBasedViewResolver viewResolver = new UrlBasedViewResolver();
//		viewResolver.setViewClass(TilesView.class);
//		return viewResolver;
//	}
//
//	/**
//	 * Configures Tiles at application startup.
//	 */
//	@Bean
//	public TilesConfigurer tilesConfigurer() {
//		TilesConfigurer configurer = new TilesConfigurer();
//		configurer.setDefinitions(new String[] {
//			"/WEB-INF/layouts/tiles.xml",
//			"/WEB-INF/views/**/tiles.xml"				
//		});
//		configurer.setCheckRefresh(true);
//		return configurer;
//	}
//	
//	/**
//	 * Messages to support internationalization/localization.
//	 */
//	@Bean
//	public MessageSource messageSource() {
//		ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
//		messageSource.setBasename("/WEB-INF/messages/messages");
//		if (environment.acceptsProfiles("embedded")) {
//			messageSource.setCacheSeconds(0);
//		}
//		return messageSource;
//	}
//
//	/**
//	 * Supports FileUploads.
//	 */
//	@Bean
//	public MultipartResolver multipartResolver() {
//		CommonsMultipartResolver multipartResolver = new CommonsMultipartResolver();
//		multipartResolver.setMaxUploadSize(500000);
//		return multipartResolver;
//	}
//	
//	// custom argument resolver inner classes
//
//	private static class AccountHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {
//
//		public boolean supportsParameter(MethodParameter parameter) {
//			return Account.class.isAssignableFrom(parameter.getParameterType());
//		}
//
//		public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest webRequest,
//				WebDataBinderFactory binderFactory) throws Exception {
//			Authentication auth = (Authentication) webRequest.getUserPrincipal();
//			return auth != null && auth.getPrincipal() instanceof Account ? auth.getPrincipal() : null;
//		}
//
//	}
//	
//	private static class DateTimeZoneHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {
//
//		public boolean supportsParameter(MethodParameter parameter) {
//			return DateTimeZone.class.isAssignableFrom(parameter.getParameterType());
//		}
//
//		public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest webRequest,
//				WebDataBinderFactory binderFactory) throws Exception {
//			return JodaTimeContextHolder.getJodaTimeContext().getTimeZone();
//		}
//		
//	}
//	
//	private static class LocationHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {
//
//		public boolean supportsParameter(MethodParameter parameter) {
//			return Location.class.isAssignableFrom(parameter.getParameterType());
//		}
//
//		public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest webRequest,
//				WebDataBinderFactory binderFactory) throws Exception {
//			return webRequest.getAttribute(UserLocationHandlerInterceptor.USER_LOCATION_ATTRIBUTE, WebRequest.SCOPE_REQUEST);
//		}
//		
//	}
}
