package org.dante.springsecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Book {
	private Long id;
	private String name;
	
	public Book() {}
}
