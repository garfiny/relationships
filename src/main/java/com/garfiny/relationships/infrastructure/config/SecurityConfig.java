package com.garfiny.relationships.infrastructure.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

@Configuration
//@ImportResource("classpath:security.xml")
public class SecurityConfig {

	private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
	
//	@Configuration
//	@Profile("embedded")
//	static class Embedded {
//
//		@Bean
//		public PasswordEncoder passwordEncoder() {
//			return NoOpPasswordEncoder.getInstance();
//		}
//		
//		@Bean
//		public TextEncryptor textEncryptor() {
//			return Encryptors.noOpText();
//		}
//
//		@Bean
//		public OAuthSessionManager oauthSessionManager(AppRepository appRepository) {
//			return new ConcurrentMapOAuthSessionManager(appRepository);
//		}
//		
//	}
//
//	@Configuration
//	@Profile("standard")
//	static class Standard {
//
//		@Inject
//		private Environment environment;
//
//		@Bean
//		public PasswordEncoder passwordEncoder() {
//			return new GreenhousePasswordEncoder(getEncryptPassword());
//		}
//
//		@Bean
//		public TextEncryptor textEncryptor() {
//			return Encryptors.queryableText(getEncryptPassword(), environment.getProperty("security.encryptSalt"));
//		}
//		
//		@Bean
//		public OAuthSessionManager oauthSessionManager(StringRedisTemplate redisTemplate, AppRepository appRepository) {
//			return new RedisOAuthSessionManager(redisTemplate, appRepository);
//		}
//
//		// helpers
//		
//		private String getEncryptPassword() {
//			return environment.getProperty("security.encryptPassword");
//		}
//		
//	}
	
	@Bean(name = "authenticationManager")
	public AuthenticationManager authenticationManager() {
		
	    PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
	    preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
	    preAuthenticatedAuthenticationProvider.afterPropertiesSet();
		
	    List<AuthenticationProvider> providers = 
	    		Arrays.<AuthenticationProvider>asList(preAuthenticatedAuthenticationProvider);
	    
	    AuthenticationManager authenticationManager = new ProviderManager(providers);
	}
	
	// accessDecisionManager
	@Bean
	public AccessDecisionManager accessDecisionManager() {
		
	    List<AccessDecisionVoter> voters = 
	    		Arrays.<AccessDecisionVoter>asList(new RoleVoter(), new WebExpressionVoter());
	    
	    return new AffirmativeBased(voters);
	}
	
    // SecurityExpressionHandler
	@Bean
	public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
		
		return new DefaultWebSecurityExpressionHandler();
	}
	
//	@Bean(name = "authenticationProvider")
//	public AuthenticationProvider authenticationProvider() {
////		org.springframework.security.authentication.dao.DaoAuthenticationProvider
//	}
	
//	@Bean
//	public PasswordEncoder passwordEncoder() {
////		org.springframework.security.authentication.encoding.Md5PasswordEncoder
//	}
	
//	@Bean
//	public AnonymousAuthenticationProvider anonymousProvider() {
////		<property name="key" value="SomeUniqueKeyForThisApplication" />
//	}
	
	// TODO define user service here
//	<bean id="userService" class="org.springframework.security.core.userdetails.memory.InMemoryDaoImpl">
//    <property name="userMap">
//        <value>
//            bob=12b141f35d58b8b3a46eea65e6ac179e,ROLE_SUPERVISOR,ROLE_USER
//            sam=d1a5e26d0558c455d386085fad77d427,ROLE_USER
//        </value>
//    </property>
//</bean>

	
	@Bean
	public FilterChainProxy springSecurityFilterChain() throws Exception {
	    // AuthenticationEntryPoint
//	    BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
//	    entryPoint.setRealmName("AppName Realm");
	    
	    // accessDecisionManager
//	    List<AccessDecisionVoter> voters = Arrays.<AccessDecisionVoter>asList(new RoleVoter(), new WebExpressionVoter());
//	    AccessDecisionManager accessDecisionManager = new AffirmativeBased(voters);
	    
	    // SecurityExpressionHandler
//	    SecurityExpressionHandler<FilterInvocation> securityExpressionHandler = new DefaultWebSecurityExpressionHandler();
	    
	    // AuthenticationUserDetailsService
//	    UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService = new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>(authUserDetailService);
//	    authenticationUserDetailsService.afterPropertiesSet();
	    
	    // PreAuthenticatedAuthenticationProvider
//	    PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
//	    preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
//	    preAuthenticatedAuthenticationProvider.afterPropertiesSet();
	    
	    // AuthenticationManager
//	    List<AuthenticationProvider> providers = Arrays.<AuthenticationProvider>asList(preAuthenticatedAuthenticationProvider);
//	    AuthenticationManager authenticationManager = new ProviderManager(providers);
	    
	    // HttpSessionSecurityContextRepository
//	    HttpSessionSecurityContextRepository httpSessionSecurityContextRepository = new HttpSessionSecurityContextRepository();
	    
	    // SessionRegistry
//	    SessionRegistry sessionRegistry = new SessionRegistryImpl();
	    
	    // ConcurrentSessionControlStrategy
//	    ConcurrentSessionControlStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlStrategy(sessionRegistry);

	    // ConcurrentSessionFilter
//	    ConcurrentSessionFilter concurrentSessionFilter = new ConcurrentSessionFilter(sessionRegistry);
//	    concurrentSessionFilter.afterPropertiesSet();
	    
	    // SecurityContextPersistenceFilter
//	    SecurityContextPersistenceFilter securityContextPersistenceFilter = new SecurityContextPersistenceFilter(httpSessionSecurityContextRepository);
	    
	    // X509AuthenticationFilter
//	    X509AuthenticationFilter x509AuthenticationFilter = new X509AuthenticationFilter();
//	    x509AuthenticationFilter.setAuthenticationManager(authenticationManager);
//	    x509AuthenticationFilter.afterPropertiesSet();
	    
	    // RequestCacheAwareFilter
//	    RequestCacheAwareFilter requestCacheAwareFilter = new RequestCacheAwareFilter();
	    
	    // SecurityContextHolderAwareRequestFilter
//	    SecurityContextHolderAwareRequestFilter securityContextHolderAwareRequestFilter = new SecurityContextHolderAwareRequestFilter();
	    
	    // SessionManagementFilter
//	    SessionManagementFilter sessionManagementFilter = new SessionManagementFilter(httpSessionSecurityContextRepository, concurrentSessionControlStrategy);
	    
	    // ExceptionTranslationFilter
//	    ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(entryPoint);
//	    exceptionTranslationFilter.setAccessDeniedHandler(new AccessDeniedHandlerImpl());
//	    exceptionTranslationFilter.afterPropertiesSet();
	    

	    
	    // SecurityFilterChain
//	    SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"),
//	            concurrentSessionFilter,
//	            securityContextPersistenceFilter,
//	            x509AuthenticationFilter,
//	            requestCacheAwareFilter,
//	            securityContextHolderAwareRequestFilter,
//	            sessionManagementFilter,
//	            exceptionTranslationFilter,
//	            filterSecurityInterceptor);
	    logger.info("================================Create Default Security Filter Chain=================");
	    SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"), 
	    		filterSecurityInterceptor());
	    
	    return new FilterChainProxy(chain);
	}
	
	// FilterSecurityInterceptor
	private FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
		
	    FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
	    filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
	    filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
	    LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> map = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
	    map.put(new AntPathRequestMatcher("/**"), 
	    		Arrays.<ConfigAttribute>asList(
	    				new org.springframework.security.access.SecurityConfig("isAuthenticated()")));
	    ExpressionBasedFilterInvocationSecurityMetadataSource ms = new ExpressionBasedFilterInvocationSecurityMetadataSource(map, securityExpressionHandler());
	    filterSecurityInterceptor.setSecurityMetadataSource(ms);
	    filterSecurityInterceptor.afterPropertiesSet();
	    return filterSecurityInterceptor;
	}
}
