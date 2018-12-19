package org.dante.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

	@GetMapping("/foo")
	public String foo() {
		return "foo";
	}
	
	@GetMapping("/bar")
	public String bar() {
		return "bar";
	}
	
}
