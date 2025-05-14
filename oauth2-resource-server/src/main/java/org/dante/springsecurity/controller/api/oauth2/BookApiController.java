package org.dante.springsecurity.controller.api.oauth2;

import cn.hutool.core.lang.Console;
import org.dante.springsecurity.controller.api.BaseApiController;
import org.dante.springsecurity.dto.BookDTO;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/book")
public class BookApiController extends BaseApiController {

	@PreAuthorize("hasAuthority('api.book.read')")
	@GetMapping("/{id}")
	public BookDTO findById(@PathVariable("id") String id, @AuthenticationPrincipal Jwt jwt) {
		if(jwt != null) {
			Console.log("====> {} - {}", jwt.getHeaders(), jwt.getClaims());
		}
		return new BookDTO(id, "书号【" + id + "】");
	}

	@PreAuthorize("hasAuthority('api.book.write')")
	@PostMapping("/{id}")
	public BookDTO addWithId(@PathVariable("id") String id) {
		return new BookDTO(id, "新书号【" + id + "】");
	}
}
