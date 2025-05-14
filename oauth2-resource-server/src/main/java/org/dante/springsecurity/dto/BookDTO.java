package org.dante.springsecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class BookDTO {
	private String id;
	private String name;
	
	public BookDTO() {}
}
