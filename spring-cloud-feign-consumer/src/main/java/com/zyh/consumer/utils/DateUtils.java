package com.zyh.consumer.utils;

import java.text.SimpleDateFormat;
import java.util.Date;

public class DateUtils {
    public static final String YMD_DASH_WITH_TIME_NO = "yyyyMMddHHmmss";
    /**
     * 获取当前时间字符串 格式 yyyyMMddHHmmss
     * @return
     */
    public static String getNowDateTimeStr() {
        Date dt = new Date();
        // 最后的aa表示“上午”或“下午” HH表示24小时制 如果换成hh表示12小时制
        SimpleDateFormat sdf = new SimpleDateFormat(YMD_DASH_WITH_TIME_NO);
        return sdf.format(dt);
    }
}
