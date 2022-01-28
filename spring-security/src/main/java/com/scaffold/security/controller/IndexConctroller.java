package com.scaffold.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexConctroller {

    @GetMapping("/index")
    public String index() {
        return "index";
    }
}
