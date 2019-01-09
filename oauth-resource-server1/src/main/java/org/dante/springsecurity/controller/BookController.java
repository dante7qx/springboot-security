package org.dante.springsecurity.controller;

import org.dante.springsecurity.dto.Book;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BookController {
	
	@PreAuthorize("#oauth2.hasScope('book') and #oauth2.hasScope('read')")
	@GetMapping("/book/{id}")
	public Book findById(@PathVariable Long id) {
		return new Book(id, "书号【" + id + "】");
	}
	
	@PreAuthorize("#oauth2.hasScope('book') and #oauth2.hasScope('write')")
	@PostMapping("/book/{id}")
	public Book addWithId(@PathVariable Long id) {
		return new Book(id, "新书号【" + id + "】");
	}
}
