package com.study.inflearnsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/hello")
@RestController
public class HelloController {
    @GetMapping
    public ResponseEntity<String> hello(){
        return ResponseEntity.ok("hello");
    }
}
