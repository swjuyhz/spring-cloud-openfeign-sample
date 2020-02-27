package com.zyh.consumer.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name= "single-producer", url="http://localhost:9100")
public interface HelloRemoteSingleClient {
	@GetMapping(value = "/hello")
    public String hello();
	
}
