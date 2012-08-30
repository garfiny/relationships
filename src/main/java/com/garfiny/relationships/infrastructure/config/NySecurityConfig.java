package com.garfiny.relationships.infrastructure.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Properties;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

import com.garfiny.relationships.infrastructure.config.annotation.Dev;
import com.garfiny.relationships.infrastructure.config.annotation.Embedded;
import com.garfiny.relationships.infrastructure.config.annotation.Production;

@Configuration
public class NySecurityConfig {

	private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

	@Inject
	private Environment environment;
	
	@Value("${login_form_url}")
	private String loginFormUrl;
	
	@Configuration
	@Embedded
	static class EmbeddedSecurityConfig {

		@Value("${login_form_url}")
		private String loginFormUrl;
		
		@Bean
		@Autowired
		public FilterChainProxy springSecurityFilterChain(FilterSecurityInterceptor filterSecurityInterceptor,
				UsernamePasswordAuthenticationFilter formLoginFilter,
				ExceptionTranslationFilter exceptionTranslationFilter,
				SecurityContextHolderAwareRequestFilter securityContextHolderAwareRequestFilter) throws Exception {
			
		    logger.info("================================Create Default Security Filter Chain=================");
//		    SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"),
//		            concurrentSessionFilter,
//		            securityContextPersistenceFilter,
//		            x509AuthenticationFilter,
//		            requestCacheAwareFilter,
//		            securityContextHolderAwareRequestFilter,
//		            sessionManagementFilter,
//		            exceptionTranslationFilter,
//		            filterSecurityInterceptor);
		    
		    List<SecurityFilterChain> filterChainList = new ArrayList<>();
		    filterChainList.add(noneSecurityFilterChain());
		    filterChainList.add(defaultFilterChain(filterSecurityInterceptor, formLoginFilter, exceptionTranslationFilter, securityContextHolderAwareRequestFilter));
		    
		    return new FilterChainProxy(filterChainList);
		}
		
		private SecurityFilterChain defaultFilterChain(
				FilterSecurityInterceptor filterSecurityInterceptor,
				UsernamePasswordAuthenticationFilter formLoginFilter,
				ExceptionTranslationFilter exceptionTranslationFilter,
				SecurityContextHolderAwareRequestFilter securityContextHolderAwareRequestFilter) {
			
		    return new DefaultSecurityFilterChain(
		    		new AntPathRequestMatcher("/**"), securityContextHolderAwareRequestFilter, 
		    		exceptionTranslationFilter, filterSecurityInterceptor);			
		}
		
		private SecurityFilterChain noneSecurityFilterChain() {
			return new DefaultSecurityFilterChain(new AntPathRequestMatcher(loginFormUrl));
		}
		
		@Bean
		@Autowired
		public FilterSecurityInterceptor filterSecurityInterceptor(
				AuthenticationManager authenticationManager, AccessDecisionManager accessDecisionManager,
				ExceptionTranslationFilter exceptionTranslationFilter,
				SecurityExpressionHandler<FilterInvocation> securityExpressionHandler) throws Exception{
			
			FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
			filterSecurityInterceptor.setAuthenticationManager(authenticationManager);
			filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager);
			
		    LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> map = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
//		    map.put(new AntPathRequestMatcher(loginFormUrl), Arrays.<ConfigAttribute>asList(new SecurityConfig("permitAll")));
		    map.put(new AntPathRequestMatcher("/**"), Arrays.<ConfigAttribute>asList(new SecurityConfig("permitAll")));
		    
		    ExpressionBasedFilterInvocationSecurityMetadataSource ms = new ExpressionBasedFilterInvocationSecurityMetadataSource(map, securityExpressionHandler);
		    filterSecurityInterceptor.setSecurityMetadataSource(ms);
		    filterSecurityInterceptor.afterPropertiesSet();
			
			return filterSecurityInterceptor;
		}
		
		@Bean
		@Autowired
		public UserDetailsService userDetailsService() {
			Properties users = new Properties();
			UserDetailsService userDetailsService = new InMemoryUserDetailsManager(users);
//			((InMemoryUserDetailsManager)userDetailsService).setAuthenticationManager(authenticationManager);
			return userDetailsService;
		}
		
		@Bean
		public AuthenticationFailureHandler authenticationFailureHandler() {
//			TODO replace this with default_login_failure_url property
			return new SimpleUrlAuthenticationFailureHandler("/login_err.jsp");
		}
		
		@Bean
		@Autowired
		public UsernamePasswordAuthenticationFilter formLoginFilter(
				AuthenticationManager authenticationManager,
				AuthenticationSuccessHandler authenticationSuccessHandler, 
				AuthenticationFailureHandler authenticationFailureHandler) {
			
			UsernamePasswordAuthenticationFilter formLoginFilter = new UsernamePasswordAuthenticationFilter();
//			TODO replace this with login_url property
			formLoginFilter.setFilterProcessesUrl("/login.jsp");
			formLoginFilter.setAuthenticationManager(authenticationManager);
//			formLoginFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
			formLoginFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
			formLoginFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
			return formLoginFilter;
		}
		
		@Bean(name = "authenticationManager")
		@Autowired
		public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
			
			AnonymousAuthenticationProvider provider = new AnonymousAuthenticationProvider("SomeUniqueKeyForThisApplication");
			DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
			daoAuthenticationProvider.setUserDetailsService(userDetailsService);
			daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
			
		    List<AuthenticationProvider> providers = 
		    		Arrays.<AuthenticationProvider>asList(provider, daoAuthenticationProvider);
		    
		    return new ProviderManager(providers);
		}
	}
	
	@Configuration
	@Production
	@Dev
	static class StandardSecurityConfig {

		@Inject
		private Environment environment;
		
		@Bean
		@Autowired
		public FilterChainProxy springSecurityFilterChain(FilterSecurityInterceptor filterSecurityInterceptor) throws Exception {
		    // SecurityFilterChain
//		    SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"),
//					ChannelProcessingFilter
//		            concurrentSessionFilter,
//		            securityContextPersistenceFilter,
//		            x509AuthenticationFilter,
//		            requestCacheAwareFilter,
//		            securityContextHolderAwareRequestFilter,
//		            sessionManagementFilter,
//		            exceptionTranslationFilter,
//		            filterSecurityInterceptor);
		    logger.info("================================Create Production Security Filter Chain=================");
		    SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"), filterSecurityInterceptor);
		    return new FilterChainProxy(chain);
		}
		
		@Bean
		public UserDetailsService userDetailsService() {
			List<UserDetails> users = new ArrayList<>(); 
			UserDetailsService userDetailsService = new InMemoryUserDetailsManager(users);
			// TODO check if We really need authentication manager 
//			((InMemoryUserDetailsManager)userDetailsService).setAuthenticationManager(authenticationManager());
			return userDetailsService;
		}
		
		// FilterSecurityInterceptor
		@Autowired
		public FilterSecurityInterceptor filterSecurityInterceptor(SecurityExpressionHandler securityExpressionHandler) throws Exception {
			
		    FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
//		    filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
//		    filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		    LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> map = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
		    map.put(new AntPathRequestMatcher("/**"), 
		    		Arrays.<ConfigAttribute>asList(
		    				new org.springframework.security.access.SecurityConfig("isAuthenticated()")));
		    ExpressionBasedFilterInvocationSecurityMetadataSource ms = new ExpressionBasedFilterInvocationSecurityMetadataSource(map, securityExpressionHandler);
		    filterSecurityInterceptor.setSecurityMetadataSource(ms);
		    filterSecurityInterceptor.afterPropertiesSet();
		    return filterSecurityInterceptor;
		}
		

		
		@Bean(name = "authenticationManager")
		public AuthenticationManager authenticationManager() {
			
//		    PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
//		    preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
//		    preAuthenticatedAuthenticationProvider.afterPropertiesSet();
//			
//		    List<AuthenticationProvider> providers = 
//		    		Arrays.<AuthenticationProvider>asList(preAuthenticatedAuthenticationProvider);
//		    
//		    AuthenticationManager authenticationManager = new ProviderManager(providers);
			// TODO
			return null;
		}
	}
	
	@Bean(name="authenticationSuccessHandler")
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		// TODO replace this with default_login_success_url property
		successHandler.setDefaultTargetUrl("/");
		return successHandler;
	}
	
	// accessDecisionManager
	@Bean
	public AccessDecisionManager accessDecisionManager() {
		
	    List<AccessDecisionVoter> voters = 
	    		Arrays.<AccessDecisionVoter>asList(new RoleVoter(), new WebExpressionVoter());
	    
	    return new AffirmativeBased(voters);
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new Md5PasswordEncoder();
	}
	
    // SecurityExpressionHandler
	@Bean
	public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
		
		return new DefaultWebSecurityExpressionHandler();
	}
	
	@Bean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		
		return new LoginUrlAuthenticationEntryPoint(loginFormUrl);
	}
	
    // ExceptionTranslationFilter
	@Bean
	@Autowired
	public ExceptionTranslationFilter exceptionTranslationFilter(AccessDeniedHandler accessDeniedHandler, AuthenticationEntryPoint authenticationEntryPoint) {
	    ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(authenticationEntryPoint);
	    exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
	    exceptionTranslationFilter.afterPropertiesSet();
	    return exceptionTranslationFilter;
	}
	
	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		AccessDeniedHandlerImpl impl = new AccessDeniedHandlerImpl();
		impl.setErrorPage(environment.getProperty("error_page"));
		return impl;
	}
	
	@Bean
	public SecurityContextHolderAwareRequestFilter SecurityContextHolderAwareRequestFilter() {
		return new SecurityContextHolderAwareRequestFilter();
	}
	
	// TODO
//	<global-method-security pre-post-annotations="enabled" />
//	GlobalMethodSecurityBeanDefinitionParser
	
//	@Bean
//	public FilterChainProxy springSecurityFilterChain() throws Exception {
	    // AuthenticationEntryPoint
//	    BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
//	    entryPoint.setRealmName("AppName Realm");
//	    
	    // accessDecisionManager
//	    List<AccessDecisionVoter> voters = Arrays.<AccessDecisionVoter>asList(new RoleVoter(), new WebExpressionVoter());
//	    AccessDecisionManager accessDecisionManager = new AffirmativeBased(voters);
//	    
	    // SecurityExpressionHandler
//	    SecurityExpressionHandler<FilterInvocation> securityExpressionHandler = new DefaultWebSecurityExpressionHandler();
//	    
	    // AuthenticationUserDetailsService
//	    UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService = new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>(authUserDetailService);
//	    authenticationUserDetailsService.afterPropertiesSet();
//	    
	    // PreAuthenticatedAuthenticationProvider
//	    PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
//	    preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
//	    preAuthenticatedAuthenticationProvider.afterPropertiesSet();
//	    
	    // AuthenticationManager
//	    List<AuthenticationProvider> providers = Arrays.<AuthenticationProvider>asList(preAuthenticatedAuthenticationProvider);
//	    AuthenticationManager authenticationManager = new ProviderManager(providers);
//	    
	    // HttpSessionSecurityContextRepository
//	    HttpSessionSecurityContextRepository httpSessionSecurityContextRepository = new HttpSessionSecurityContextRepository();
//	    
	    // SessionRegistry
//	    SessionRegistry sessionRegistry = new SessionRegistryImpl();
//	    
	    // ConcurrentSessionControlStrategy
//	    ConcurrentSessionControlStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlStrategy(sessionRegistry);
//
	    // ConcurrentSessionFilter
//	    ConcurrentSessionFilter concurrentSessionFilter = new ConcurrentSessionFilter(sessionRegistry);
//	    concurrentSessionFilter.afterPropertiesSet();
//	    
	    // SecurityContextPersistenceFilter
//	    SecurityContextPersistenceFilter securityContextPersistenceFilter = new SecurityContextPersistenceFilter(httpSessionSecurityContextRepository);
//	    
	    // X509AuthenticationFilter
//	    X509AuthenticationFilter x509AuthenticationFilter = new X509AuthenticationFilter();
//	    x509AuthenticationFilter.setAuthenticationManager(authenticationManager);
//	    x509AuthenticationFilter.afterPropertiesSet();
//	    
	    // RequestCacheAwareFilter
//	    RequestCacheAwareFilter requestCacheAwareFilter = new RequestCacheAwareFilter();
//	    
	    // SecurityContextHolderAwareRequestFilter
//	    SecurityContextHolderAwareRequestFilter securityContextHolderAwareRequestFilter = new SecurityContextHolderAwareRequestFilter();
//	    
	    // SessionManagementFilter
//	    SessionManagementFilter sessionManagementFilter = new SessionManagementFilter(httpSessionSecurityContextRepository, concurrentSessionControlStrategy);
//	    
	    // ExceptionTranslationFilter
//	    ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(entryPoint);
//	    exceptionTranslationFilter.setAccessDeniedHandler(new AccessDeniedHandlerImpl());
//	    exceptionTranslationFilter.afterPropertiesSet();
//
//	    
//	    SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"),
//	            concurrentSessionFilter,
//	            securityContextPersistenceFilter,
//	            x509AuthenticationFilter,
//	            requestCacheAwareFilter,
//	            securityContextHolderAwareRequestFilter,
//	            sessionManagementFilter,
//	            exceptionTranslationFilter,
//	            filterSecurityInterceptor);
//	    logger.info("================================Create Default Security Filter Chain=================");
//	    SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"), 
//	    		filterSecurityInterceptor());
//	    
//	    return new FilterChainProxy(chain);
//	}
}
