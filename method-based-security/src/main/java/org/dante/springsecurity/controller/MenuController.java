package org.dante.springsecurity.controller;

import org.dante.springsecurity.config.InitDataConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/menu")
public class MenuController {

	@GetMapping("/add/{menu}")
	@PreAuthorize("hasAuthority('" + InitDataConfig.AUTH_MENU_ADD + "')")
	public String addMenu(@PathVariable String menu) {
		return menu.concat("添加成功！");
	}

	@DeleteMapping("/delete/{menu}")
	@PreAuthorize("hasAuthority('" + InitDataConfig.AUTH_MENU_DEL + "')")
	public String delMenu(@PathVariable String menu) {
		return menu.concat("删除成功！");
	}

}
