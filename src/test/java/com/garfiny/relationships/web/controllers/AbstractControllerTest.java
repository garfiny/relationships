package com.garfiny.relationships.web.controllers;

import static org.junit.Assert.assertNotNull;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.servlet.HandlerAdapter;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.ModelAndView;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration({"classpath:/spring/root-context.xml"})
public class AbstractControllerTest {

    @Inject
    private ApplicationContext applicationContext;

    private HandlerAdapter handlerAdapter;

    @Before
    public void setUp() throws Exception {

        this.handlerAdapter = applicationContext.getBean(HandlerAdapter.class);
    }

    protected ModelAndView handle(HttpServletRequest request, HttpServletResponse response, Object controller)
            throws Exception {
        final HandlerMapping handlerMapping = applicationContext.getBean(HandlerMapping.class);
        final HandlerExecutionChain handler = handlerMapping.getHandler(request);
        assertNotNull("No handler found for request, check you request mapping", handler);

        final HandlerInterceptor[] interceptors =
            handlerMapping.getHandler(request).getInterceptors();
        
        for (HandlerInterceptor interceptor : interceptors) {
        	
            final boolean carryOn = interceptor.preHandle(request, response, controller);
            if (!carryOn) {
                return null;
            }
        }

        final ModelAndView mav = handlerAdapter.handle(request, response, controller);
        return mav;
    }
}
