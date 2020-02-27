package com.zyh.consumer.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name= "spring-cloud-producer")
public interface HelloRemoteClient {
	@GetMapping(value = "/hello")
    public String hello();
	
}
