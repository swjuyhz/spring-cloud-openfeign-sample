/**
 * ============================================================================       
 * = COPYRIGHT		          
 *          PAX Computer Technology(Shenzhen) CO., LTD PROPRIETARY INFORMATION		
 *   This software is supplied under the terms of a license agreement or nondisclosure 	
 *   agreement with PAX Computer Technology(Shenzhen) CO., LTD and may not be copied or 
 *   disclosed except in accordance with the terms in that agreement.       
 *       Copyright (C) 2018-? PAX Computer Technology(Shenzhen) CO., LTD All rights reserved.    
 * Description:       
 * Revision History:      
 * Date                         Author                    Action
 * 2018年11月8日 下午3:40:19           liming                   StringUtil
 * ============================================================================
 */
package com.zyh.consumer.utils;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.bcel.classfile.Constant;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties.Admin;

import freemarker.template.utility.DateUtil;

public class StringUtil {
	
	public static final String DELIMETER_="_";
    
    public static String getRandomNumbers() {
        return UUID.randomUUID().toString().trim().replace("-", "");
    }

    public static String getRandomStrByLength(int length) {
        String base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }
    
    public static String getRandomNumByLength(int length) {
        String base = "1234567890";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }
    
    public static String getCustomEmailContentStr(List<String> contents,String adminName) {
        StringBuilder contentBuf = new StringBuilder();
        contentBuf.append("Dear ").append(adminName).append(",</br></br>");
        for(String content : contents) {
        	contentBuf.append(content)
            		  .append("</br>");
        }
        contentBuf.append("</br>");
        contentBuf.append("Best regards,</br>");
        contentBuf.append("PAX Support Team");
        return contentBuf.toString();
    }
    
    /**
     * 去掉字符串不可见字符与首尾空格
     * @param src
     * @return
     */
    public static String trimStrictly(final String src) {
    	if(null == src) {
    		return "";
    	}
		StringBuilder strBuilder = new StringBuilder();
		src.codePoints().forEach((i) -> {
			//去掉不可见字符
			if(!Character.isIdentifierIgnorable(i)) {
				strBuilder.append(Character.toChars(i));
			}
		});
		return strBuilder.toString().trim();
    }
    /**
     * @Description: 字符串转十六进制
     * @param str
     * @return
     * @return: String
     */
    public static String str2Hex(String str) {
        char[] chars = str.toCharArray();

        StringBuffer hex = new StringBuffer();
        for (int i = 0; i < chars.length; i++) {
            hex.append(Integer.toHexString((int) chars[i]));
        }

        return hex.toString();
    }
    /**
     * @Description: 16进制转字符串
     * @param hex
     * @return
     * @return: String
     */
    public static String hex2String(String hex) {
        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();

        for (int i = 0; i < hex.length() - 1; i += 2) {
            String output = hex.substring(i, (i + 2));
            int decimal = Integer.parseInt(output, 16);
            sb.append((char) decimal);
            temp.append(decimal);
        }
        return sb.toString();
    }

    public static byte asc2Bcd(byte asc) {
        byte bcd = 0;
        if ((asc >= '0') && (asc <= '9')) {
            bcd = (byte) (asc - '0');
        } else if ((asc >= 'A') && (asc <= 'F')) {
            bcd = (byte) (asc - 'A' + 10);
        } else if ((asc >= 'a') && (asc <= 'f')) {
            bcd = (byte) (asc - 'a' + 10);
        } else {
            bcd = (byte) (asc - 48);
        }
        return bcd;
    }
/**
 * 
 * @Description: ASCII转BCD
 * @param asciiArray
 * @param ascLen
 * @return
 * @return: byte[]
 */
    public static byte[] ascii2bcd(byte[] asciiArray, int ascLen) {
        byte[] bcdArray = new byte[ascLen / 2];
        int j = 0;
        for (int i = 0; i < (ascLen + 1) / 2; i++) {
            bcdArray[i] = asc2Bcd(asciiArray[j++]);
            bcdArray[i] = (byte) (((j >= ascLen) ? 0x00 : asc2Bcd(asciiArray[j++])) + (bcdArray[i] << 4));
        }
        return bcdArray;
    }
    /**
     * 
     * @Description: BCD码转字符串
     * @param bytes
     * @return
     * @return: String
     */
    public static String bcd2Str(byte[] bytes) {
        char temp[] = new char[bytes.length * 2];
        char val = 0;

        for (int i = 0; i < bytes.length; i++) {
            val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);
            temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');

            val = (char) (bytes[i] & 0x0f);
            temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');
        }
        return new String(temp);
    }
    
    public static void main(String[] args) throws UnsupportedEncodingException {
    	
    }
}
