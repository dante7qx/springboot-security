package org.dante.springsecurity.controller;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {
	
	@GetMapping("/add/{user}")
	public String addUser(@PathVariable String user) {
		return user.concat("添加成功！");
	}
	
	@DeleteMapping("/delete/{user}")
	public String delUser(@PathVariable String user) {
		return user.concat("删除成功！");
	}
	
}
