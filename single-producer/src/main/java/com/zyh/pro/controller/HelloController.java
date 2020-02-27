package com.zyh.pro.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/hello")
public class HelloController {
	
	@GetMapping
	public String helloWord() {
		return "Hello Word!--from single producer.";
	}

}
