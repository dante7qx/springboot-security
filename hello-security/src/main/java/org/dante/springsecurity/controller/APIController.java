package org.dante.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class APIController {

    @GetMapping("/public")
    public String publicApi() {
        return "public api";
    }

    @GetMapping("/public/{info}")
    public String publicApi(@PathVariable("info") String info) {
        return "public api - " + info;
    }

    @GetMapping("/user")
    public String userApi() {
        return "user api";
    }

    @GetMapping("/user/{info}")
    public String userApi(@PathVariable("info") String info) {
        return "user api - " + info;
    }

}
