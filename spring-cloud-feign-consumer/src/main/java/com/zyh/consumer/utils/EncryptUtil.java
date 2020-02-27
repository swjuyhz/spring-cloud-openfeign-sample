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
 * 2018年11月8日 下午4:18:34           liming                   EncryptUtil
 * ============================================================================
 */
package com.zyh.consumer.utils;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.zyh.consumer.bean.IRkiServerBean;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EncryptUtil {
    
    private static final String ALGORITHM = "DESede"; //定义加密算法DESede(即3DES)
    /**RSA加密所用私钥*/
    private static final String RSA_PRIVATE_KEY = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKAMF1sNzPCRngszZ+YAfcUL9MFuWg34/hHMMHc/TdwUrAahPBrVQuDrsO58mHr5J5sfP67Qcz0dnfrnurYXDgG6f11q8aPQGH/JMX0FB49FfEt7iSlGat+2hUFOPfYRIyiOzgYtsQ8m2DYjL2I5ppWkj3xQ1U12R6gQQ1AYw7rNAgMBAAECgYEAnTqjqzkIj4GOsNREiskKxYy0W17Mq5NkDhn5tvyCweWxBiZZxMajmBETVYcjyROCXDs7tcJko7K346jJXV+SyoG32uDe1Rf3W042ut/ju3nzm7CBb6YUwmujUnZNR8sYOY7UAO1mCqX9WiUbPZ22arBaSoD8MmEGjdajM1pII6UCQQDiZArghT6hhYri0l53RHjIu5D0W4cWIv1arDHuC4jpYc+PoL5+8oOQc3U+w0d1dmcAU8BnCy3HPWiqTBJx8O0jAkEAtPrAPswSIbmi1jI7S5d0mve6mmcX05gFywshy4gb97f6I+YcY1j/LPXkcxxf8tMycZanjdEwIus4zAryanyPTwJAS/cz6yjq3jo4Y2ohxrWULg86UbSQvK3bA9z6GB2IwH9QrapLob9wxDzp37iZNuIXJ/XyfuEyaEPD5jkGi3NDrwJBAKU6XPO4KkGiErmNyLbdwraMv0+iGY2zuG5Ebok8bZQ+4l+OAZLuOKIaqIQzfqHaEa7EhZqjRlhK+mLHB8USjV8CQQCMyyQE/uSClK1BgXeOK48mYaFu+Grlcve4xYa3rNPC9J652dE1i2kz2c6hY1/vM3mUCECqzwLf94j85+VI/nY2";
    /**RSA加密所用钥*/
    private static final String RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgDBdbDczwkZ4LM2fmAH3FC/TBbloN+P4RzDB3P03cFKwGoTwa1ULg67DufJh6+SebHz+u0HM9HZ3657q2Fw4Bun9davGj0Bh/yTF9BQePRXxLe4kpRmrftoVBTj32ESMojs4GLbEPJtg2Iy9iOaaVpI98UNVNdkeoEENQGMO6zQIDAQAB";
    /**
     * 根据指定的加密算法，返回加密后的16进制字符串。
     * 
     * @param content
     * @param algorithm
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String encrypt(String content, String algorithm) throws NoSuchAlgorithmException {
        byte[] bytes = content.getBytes();
        MessageDigest msgDigest = MessageDigest.getInstance(algorithm);
        msgDigest.update(bytes);
        byte[] digestBytes = msgDigest.digest();
        String hexDigest = new String(Hex.encodeHex(digestBytes));

        return hexDigest;
    }
    /**
     * @Description: SHA256加密
     * @param source
     * @return
     * @return: String
     */
    public static String sha256(String source) {
        return DigestUtils.sha256Hex(source);
    }
    /**
     * @Description: MD5加密
     * @param source
     * @return
     * @return: String
     */
    public static String md5Encode(String source){
        return DigestUtils.md5Hex(source);
    }
    /**
     * @Description: base64加密
     * @param source
     * @return
     * @return: String
     */
    public static String base64Encrypt(String source) {
        Base64 base64 = new Base64();
        return  new String(base64.encode(source.getBytes())).replace("\r", "").replace("\n", "").replace("=", "")
                .replace("+", "*").replace("/", "-").replace("-x", "-xx").replace("*", "-x-");
    }
    /**
     * 
     * @Description: base64解密
     * @param source
     * @return
     * @return: String
     */
    public static String base64Decrypt(String source) {
        String result = "";
        result = new String((new Base64()).decode(source.replace("-x-", "*").replace("-xx", "-x").replace("*", "+").replace("-", "/")+ "="));
        return result;
    }
    
    /**
     * 转换成base64编码
     */
    public static String byte2Base64(byte[] b) {
        Base64 base64 = new Base64();
        return new String(base64.encode(b));
    }
    
    /**
     * 3des解码
     * @param value 待解密字符串
     * @param key   原始密钥字符串
     * @return
     * @throws Exception
     */
    public static String decrypt3DES(String value, String key) {
        byte[] b = new byte[0];
        try {
            Base64 base64 = new Base64();
            b = decryptMode(getKeyBytes(key), base64.decode(value));
        } catch (Exception e) {
            log.error("[Decrypt3DES]-->3des解码失败",e);
        }
        return new String(b);
    }

    /**
     * 3des加密
     * @param value 待加密字符串
     * @param key   原始密钥字符串
     * @return
     * @throws Exception
     */
    public static String encrypt3DES(String value, String key) {
        return byte2Base64(encryptMode(getKeyBytes(key), value.getBytes()));
    }
    
    /**
     * 加密
     * @param keybyte 密钥，长度为24字节
     * @param keybyte 密钥，长度为24字节
     * @param src     为被加密的数据缓冲区（源）
     * @return
     */
    public static byte[] encryptMode(byte[] keybyte, byte[] src) {
        try {
            // 生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, ALGORITHM); // 加密
            Cipher c1 = Cipher.getInstance(ALGORITHM);
            c1.init(Cipher.ENCRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (NoSuchAlgorithmException e1) {
            log.error("加密失败",e1);
        } catch (javax.crypto.NoSuchPaddingException e2) {
            log.error("加密失败",e2);
        } catch (Exception e3) {
            log.error("加密失败",e3);
        }
        return new byte[0];
    }

    /**
     * 解密
     * @param keybyte 解密密钥，长度为24字节
     * @param src     解密后的缓冲区
     * @return
     */
    public static byte[] decryptMode(byte[] keybyte, byte[] src) {
        try {
            // 生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, ALGORITHM);
            // 解密
            Cipher c1 = Cipher.getInstance(ALGORITHM);
            c1.init(Cipher.DECRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (NoSuchAlgorithmException e1) {
            log.error("解密失败",e1);
        } catch (javax.crypto.NoSuchPaddingException e2) {
            log.error("解密失败",e2);
        } catch (Exception e3) {
            log.error("解密失败",e3);
        }
        return new byte[0];
    }
    /**
     * 计算24位长的密码byte值,首先对原始密钥做MD5算hash值，再用前8位数据对应补全后8位
     * @param strKey 密钥
     * @return
     * @throws Exception
     */
    public static byte[] getKeyBytes(String strKey) {
        byte[] bkey24 = new byte[24];
        if (null == strKey || strKey.length() < 1){
            try {
                throw new Exception("key is null or empty!");
            } catch (Exception e) {
                return bkey24;
            }
        }
        MessageDigest alg = null;
        try {
            alg = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            log.error("初始化MessageDigest失败");
        }
        if(null == alg){
            return bkey24;
        }
        alg.update(strKey.getBytes());
        byte[] bkey = alg.digest();
        int start = bkey.length;
        for (int i = 0; i < start; i++) {
            bkey24[i] = bkey[i];
        }
        for (int i = start; i < 24; i++) {// 为了与.net16位key兼容
            bkey24[i] = bkey[i - start];
        }
        return bkey24;
    }
    
    /**
     * 用户加密接口
     * @param pwd
     * @param salt
     * @return
     */
    public static String userPwdEncodeTT(String pwd,String salt) {
    	return EncryptUtil.sha256(EncryptUtil.sha256(pwd) + salt);
    }
    
    /**
     * @Description: MD5加密下载记录作为redis key
     * @param source
     * @return
     * @return: String
     */
    public static String md5Encode(String taskId,String downloadTime,String downloadStatus,String sn){
        String link = "-";
    	return DigestUtils.md5Hex(taskId+link+downloadTime+link+downloadStatus+link+sn);
    }
    
    /**
     * sha256_HMAC加密
     * @param message 消息
     * @param secret  秘钥
     * @return 加密后转Base64字符串
     */
    public static String hmacSHA256_Base64(String message, String secret) {
        String hash = "";
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            byte[] bytes = sha256_HMAC.doFinal(message.getBytes());
            hash = byte2Base64(bytes);
        } catch (Exception e) {
            log.error("Error HmacSHA256 =={}" , e.getMessage());
        }
        return hash;
    }
    
    /** 
     * 随机生成密钥对 
     * @throws NoSuchAlgorithmException 
     */  
    public static Map<Integer, String> rsaGenKeyPair() throws NoSuchAlgorithmException { 
        Map<Integer, String> keyMap = new HashMap<>();  //用于封装随机产生的公钥与私钥
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象  
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
        // 初始化密钥对生成器，密钥大小为96-1024位  
        keyPairGen.initialize(2048,new SecureRandom());  
        // 生成一个密钥对，保存在keyPair中  
        KeyPair keyPair = keyPairGen.generateKeyPair();  
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥  
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥  
        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));  
        // 得到私钥字符串  
        String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));  
        // 将公钥和私钥保存到Map
        keyMap.put(0,publicKeyString);  //0表示公钥
        keyMap.put(1,privateKeyString);  //1表示私钥
        return keyMap;
    }  
    /** 
     * RSA公钥加密 
     *  
     * @param str 
     *            加密字符串
     * @param publicKey 
     *            公钥 
     * @return 密文 
     * @throws Exception 
     *             加密过程中的异常信息 
     */  
    public static String rsaEncrypt( String str, String publicKey ) throws Exception{
        //base64编码的公钥
        byte[] decoded = Base64.decodeBase64(publicKey);
//        byte[] decoded = publicKey.getBytes();
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
        return outStr;
    }

    /** 
     * RSA私钥解密
     *  
     * @param str 
     *            加密字符串
     * @param privateKey 
     *            私钥 
     * @return 铭文
     * @throws Exception 
     *             解密过程中的异常信息 
     */  
    public static String rsaDecrypt(String str, String privateKey) throws Exception{
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] decoded = Base64.decodeBase64(privateKey);  
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));  
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputByte),"UTF-8");
        return outStr;
    }
    
    //解密
    public static String decryptData(String data) throws IOException, InvalidCipherTextException {
 
        AsymmetricBlockCipher cipher = new RSAEngine();
        byte[] encryptDataBytes=Base64.decodeBase64(data);
 
        //解密
        byte[] privateInfoByte=Base64.decodeBase64(RSA_PRIVATE_KEY);
        AsymmetricKeyParameter priKey = PrivateKeyFactory.createKey(privateInfoByte);
        cipher.init(false, priKey);//false表示解密
 
        byte[] decryptDataBytes=cipher.processBlock(encryptDataBytes, 0, encryptDataBytes.length);
        String decryptData = new String(decryptDataBytes,"utf-8");
        return decryptData;
    }
    

    
    public static void main(String[] args) {
    	IRkiServerBean.ModelInfo mi = new IRkiServerBean.ModelInfo();
    	System.out.println(mi);
    }
}
