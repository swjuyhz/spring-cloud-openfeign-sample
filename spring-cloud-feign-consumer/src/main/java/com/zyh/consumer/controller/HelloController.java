package com.zyh.consumer.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.zyh.consumer.bean.IRkiServerBean;
import com.zyh.consumer.client.HelloRemoteClient;
import com.zyh.consumer.client.HelloRemoteSingleClient;
import com.zyh.consumer.client.RkiServerClient;

@RestController
public class HelloController {
	
	@Autowired
    HelloRemoteClient helloRemoteClient;
	@Autowired
	HelloRemoteSingleClient helloRemoteSingleClient;
	@Autowired
	RkiServerClient rkiServerClient;
	
	@GetMapping("/hello/remote/test")
	public String invokeHelloRemote() {
		String helloWord = "Remote invote test: " + helloRemoteClient.hello();
		System.out.println(helloWord);
		return helloWord;
	}
	
	@GetMapping("/hello/single/remote/test")
	public String invokeHelloSingleRemote() {
		String helloWord = "Remote invote test: " + helloRemoteSingleClient.hello();
		System.out.println(helloWord);
		return helloWord;
	}
	
	@GetMapping("/rkiserver/models")
	public String getModels() {
		String helloWord = "Remote invote RkiServer test,models info: " + rkiServerClient.getModelInfo(new IRkiServerBean.ModelInfo());
		System.out.println(helloWord);
		return helloWord;
	}
}
