package com.zyh.consumer.bean;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang.StringUtils;
import com.zyh.consumer.utils.DateUtils;
import com.zyh.consumer.utils.EncryptUtil;
import com.zyh.consumer.utils.StringUtil;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

public interface IRkiServerBean {
	String KEY = "0WjcblKhpCGs6PUUtrb03unjiJDuVPwC";
	 /**
     * 签名算法
     * @param o 要参与签名的Map数据
     * @return 签名
     * @throws IllegalAccessException
     */
    default String signSHA256(RkiServerBean rb,String key){
    	Map<String, String> map = null;
		try {
			map = BeanUtils.describe(rb);
		} catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		}
        ArrayList<String> list = new ArrayList<>();
        for(Map.Entry<String,String> entry:map.entrySet()){
        	String value = (String)entry.getValue();
            if(StringUtils.isNotEmpty(value) && !"sign".equals(value)){
                list.add(entry.getKey() + "=" + value + "&");
            }
        }
        int size = list.size();
        String [] arrayToSort = list.toArray(new String[size]);
        Arrays.sort(arrayToSort, String.CASE_INSENSITIVE_ORDER);
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < size; i ++) {
            sb.append(arrayToSort[i]);
        }
        String result = sb.toString();
        result += "key=" + key;
        result = EncryptUtil.sha256(result);
        return result;
    }
    
    @Data
    public class RkiServerBean implements IRkiServerBean{
    	/*
    	 * url = https://192.168.0.156:35449/rki
    	 * partnerid = 1010120190115005229001 
    	 * key =0WjcblKhpCGs6PUUtrb03unjiJDuVPwC
    	 */
        private String version="V1.0";
        private String signtype="sha256";
        private String partnerid = "1010120190115005229001";
        private String taskid = StringUtil.getRandomNumbers(); // 请求标识,唯一标识一笔请求，外部系统应保证唯一性,UUID
        private String random = StringUtil.getRandomStrByLength(16);// 随机数,1234567890abcdef
        private String reqtime = DateUtils.getNowDateTimeStr();// 请求时间,请求发起时间，格式：20180807110324
    }
    
    @Data
	@ToString(callSuper = true)
	@EqualsAndHashCode(callSuper = true)
    public class ModelInfo extends RkiServerBean{
    	 private String method = "getmodelinfo";
         private String sign = signSHA256(this,KEY);
    }
    
}
