package com.zyh.zuul;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@SpringBootApplication
@EnableZuulProxy //启用 zuul,自带熔断
public class SpringCloudGatewayZuulApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringCloudGatewayZuulApplication.class, args);
	}

}
