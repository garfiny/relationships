package com.garfiny.relationships.web.controllers;

import static org.springframework.test.web.ModelAndViewAssert.assertViewName;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.servlet.ModelAndView;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration({"classpath:/spring/root-context.xml"})
public class HomeControllerTest extends AbstractControllerTest {

	private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private HomeController controller;
	
    @Inject
    private ApplicationContext applicationContext;
    
	@Before
	public void setUp() {
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		controller = new HomeController();
	}
	
	@Test
	public void testHome() throws Exception {
		request.setRequestURI("/");
		final ModelAndView mv = super.handle(request, response, controller);
		assertViewName(mv, "view");
	}

}
