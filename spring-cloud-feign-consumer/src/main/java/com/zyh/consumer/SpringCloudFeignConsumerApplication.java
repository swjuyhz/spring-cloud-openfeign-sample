package com.zyh.consumer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.hystrix.dashboard.EnableHystrixDashboard;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableEurekaClient
@EnableFeignClients  //已自动集成Hystrix
@EnableHystrixDashboard
@EnableCircuitBreaker
public class SpringCloudFeignConsumerApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringCloudFeignConsumerApplication.class, args);
	}

}
