package com.garfiny.relationships.infrastructure.config;

import javax.servlet.FilterRegistration.Dynamic;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.DispatcherServlet;

public class SpringWebApplicationInitializer implements WebApplicationInitializer {

	private static final Logger logger = LoggerFactory.getLogger(SpringWebApplicationInitializer.class);
	
	@Override
	public void onStartup(ServletContext container) throws ServletException {
		
		logger.info("Relationships Application On Startup....................");
		
		// Create the 'root' Spring application context
		AnnotationConfigWebApplicationContext rootContext = new AnnotationConfigWebApplicationContext();
		rootContext.register(ApplicationConfig.class, MvcConfig.class);
		rootContext.scan("com.garfiny.relationships.infrastructure.config");
//		rootContext.getEnvironment().setDefaultProfiles("embedded");
		
		// Manage the lifecycle of the root application context
		container.addListener(new ContextLoaderListener(rootContext));
		
		// make the application use spring security framework
		addSecurityAbility(container);

		// Allows attributes to be accessed on the next request
		// TODO figure out what's FlashMapFilter
//		container.addFilter("flashMapFilter", FlashMapFilter.class).addMappingForUrlPatterns(null, false, "/*");
		
	    // Register and map the dispatcher servlet
	    ServletRegistration.Dynamic dispatcher = 
	    		container.addServlet("dispatcher", new DispatcherServlet(rootContext));
	    dispatcher.setLoadOnStartup(1);
	    dispatcher.addMapping("/");
	    logger.info("Finished Web Application Config!");
	    
//	    Set<String> mappingConflicts = dispatcher.addMapping("/");
//	    if (!mappingConflicts.isEmpty()) {
//	    	throw new IllegalStateException("'appServlet' could not be mapped to '/' due " +
//	    		"to an existing mapping. This is a known issue under Tomcat versions " +
//	    		"<= 7.0.14; see https://issues.apache.org/bugzilla/show_bug.cgi?id=51278");
//	    }
	    // H2 Database Console for managing the app's database
//	    ServletRegistration.Dynamic h2Servlet = 
//	    		sc.addServlet("H2Console", org.h2.server.web.WebServlet.class);
//	    h2Servlet.setInitParameter("webAllowOthers", "true");
//	    h2Servlet.setLoadOnStartup(2);
//	    h2Servlet.addMapping("/admin/h2/*");
	}
	
	private void addSecurityAbility(ServletContext container) {
		Dynamic filter = container.addFilter("springSecurityFilterChain", DelegatingFilterProxy.class);
		filter.addMappingForUrlPatterns(null, false, "/*");
	}

}
