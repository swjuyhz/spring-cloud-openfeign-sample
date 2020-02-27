package com.zyh.consumer.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;

import com.zyh.consumer.bean.IRkiServerBean;
import com.zyh.consumer.config.RkiServerFeignConfig;

@FeignClient(name= "rki-server", url="https://192.168.0.156:35449/rki", configuration = RkiServerFeignConfig.class, primary = false, qualifier = "rkiServerClient")
public interface RkiServerClient {
	
	@PostMapping(value = "/api/getModelInfo")
    public String getModelInfo(IRkiServerBean.ModelInfo mi);
	
	
}
