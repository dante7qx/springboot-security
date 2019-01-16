package org.dante.springsecurity;

import org.junit.Test;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class BasicTest {
	
	/**
	 * 数字运算表达式，因为先进行等式右边的运算，再赋值给等式左边的变量，所以等式两边的类型要一致
	 * 
	 * 1. int与int相除后，哪怕被赋值给float或double，结果仍然是四舍五入取整的int。
	 * 2. 需要强制将除数或被除数转换为float或double。
	 */
	@Test
	public void testCal() {
		double c = 24/7;	
		double d = (double) 24/7;
		log.info("c -> {}, d -> {}", c, d);
	}
	
}
