package org.vcc.ip2location.utils;

import java.math.BigInteger;

public class IPUtils {

	public static final int NUM_CONVERTER = 16777215;
	private static final String IPADDRESS_PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
			+ "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
			+ "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
			+ "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";

	/**
	 * Conver 1 so to ip example:985333785 =58.187.0.25
	 * 
	 * @param number
	 *            : ip format long- 
	 * @param rangeIsThree
	 *            true/false convert khong day du 3 phan dau/day du
	 * @return
	 */
	public static String convertNumberToIp(long number, boolean rangeIsThree) {
		String result = "";
		if (!rangeIsThree) {
			final int range1 = (int) (long) number >>> 24;
			final int range2 = (int) ((long) number >>> 16) & 255;
			final int range3 = (int) (long) number >>> 8 & 255;
			final int range4 = (int) (long) number & 255;
			result = String.format("%d.%d.%d.%d", range1, range2, range3,
					range4);
		} else {
			final int range1 = (int) (long) number >>> 16;
			final int range2 = (int) (long) number >>> 8 & 255;
			final int range3 = (int) (long) number & 255;
			result = String.format("%d.%d.%d", range1, range2, range3);
		}

		return result;
	}

	public static String convertNumberToIp(long number) {
		String result = "";

		final int range1 = (int) (long) number >>> 24;
		final int range2 = (int) ((long) number >>> 16) & 255;
		final int range3 = (int) (long) number >>> 8 & 255;
		final int range4 = (int) (long) number & 255;
		result = String.format("%d.%d.%d.%d", range1, range2, range3, range4);
		return result;
	}

	/**
	 * Convert 1 ip thanh 1 so long
	 * 
	 * @param ip
	 *            : dia chi ip can convert
	 * @param rangeIsThree
	 *            : true/false:
	 * @return long ip
	 */
	public static long convertIpToNumber(String ip, boolean rangeIsThree) {
		String[] listRange = ip.split("\\.");

		if (listRange.length > 4 || listRange.length < 3) {
			return 0;
		}

		long result = 0;

		if (rangeIsThree) {
			result = (Integer.parseInt(listRange[0]) << 16)
					| (Integer.parseInt(listRange[1]) << 8)
					| Integer.parseInt(listRange[2]);
		} else {
			result = (Long.parseLong(listRange[0]) << 24)
					| (Long.parseLong(listRange[1]) << 16)
					| (Long.parseLong(listRange[2]) << 8)
					| (Long.parseLong(listRange[3]));
		}

		return result;
	}

	public static long convertIpToNumber(String ip) {
		String[] listRange = ip.split("\\.");
		return (Long.parseLong(listRange[0]) << 24)
				| (Long.parseLong(listRange[1]) << 16)
				| (Long.parseLong(listRange[2]) << 8)
				| (Long.parseLong(listRange[3]));
		// return IPUtils.convertIpToNumber(ip, false);
	}

	public static long getMaxNumberOfRangeIp(String rangeIp) {
		String[] strs = rangeIp.split("/");

		final int mask = Integer.parseInt(strs[1].trim());
		final long minNumber = convertIpToNumber(strs[0].trim(), true);
		final int converter = NUM_CONVERTER >>> mask;
		long result = minNumber | converter;

		return result;
	}

	public static long getMinNumberOfRangeIp(String rangeIp) {
		String[] strs = rangeIp.split("/");
		long minNumber = convertIpToNumber(strs[0].trim(), true);

		return minNumber;
	}

	public static long getNetMask(long address, int nBitMask) {
		return address & ~((long)(1 << (32 - nBitMask)) - 1);
	}

	public static long getNetMask(String address, int nBitMask) {
		if (!address.matches(IPADDRESS_PATTERN)) {
			System.err.println("Not Invalid address");
		}
		return getNetMask(convertIpToNumber(address, false), nBitMask);
	}

	
	
	/*
	 * IPv6's common utils
	 * */

	public static long[] ipV6ToLong(String addr) {
		addr = getOriginalIp(addr);
		String[] addrArray = addr.split(":");//a IPv6 adress is of form 2607:f0d0:1002:0051:0000:0000:0000:0004

		
	    long[] num = new long[addrArray.length];

	    for (int i=0; i<addrArray.length; i++) {
	        num[i] = Long.parseLong(addrArray[i], 16);
	    }
	    long init = Long.valueOf(0);
	    long long1 = (init<<16)+num[0];
	    for (int i=1;i<4;i++) {
	        long1 = (long1<<16) + num[i];
	    }
	    long long2 = num[4];
	    for (int i=5;i<8;i++) {
	        long2 = (long2<<16) + num[i];
	    }

	    long[] longs = {long2, long1};
	    return longs;
	}


	public static String longToIpv6(long[] ip) {
	    String ipString = "";
	    for (long crtLong : ip) {//for every long: it should be two of them

	        for (int i=0; i<4; i++) {//we display in total 4 parts for every long
	            ipString = Long.toHexString(crtLong & 0xFFFF) + ":" + ipString;
	            crtLong = crtLong >> 16;
	        }
	    }
	    return ipString.substring(0,ipString.length()-1);

	}

	public static String getOriginalIp(String ip){
		int startIndex=ip.indexOf("::");
		String[] couple = ip.split("::");
	    if(startIndex!=-1){
	       if(couple.length<2){
	    	  ip+="0";
	    	  couple = ip.split("::");
	       }
	       int numClusters = couple[0].split(":").length+couple[1].split(":").length;
	       String originalIp = couple[0];
	       for(int i = 0; i< 8-numClusters; i++){
	    	   originalIp+=":"+"0";
	       }
	       ip = originalIp+":"+couple[1];
	       return ip;
	    }else{
	    	return ip;
	    }
	}
	
	public static boolean isIpv6(String address){
		return address.contains(":")?true:false;
	}
	
	public static long[] getNetMaskV6(long[] address, int nBitmask){
		String ip = longToIpv6(address);
		System.out.println("IP: "+ip);
		for(long l: address)
			System.out.println(l);
		if(nBitmask == 64){
			return new long[] {0,address[1]};
		}else{
			// nbitmask < 64
			System.out.println(longToIpv6(new long[]{0,Long.valueOf((address[1]>>(64-nBitmask))<<(64-nBitmask))}));
			return new long[] {0,(address[1]>>(64-nBitmask))<<(64-nBitmask)};
		}
		
	}
	
	public static long[] getNetMaskV6(String address, int nBitmask){
		return getNetMaskV6(ipV6ToLong(address), nBitmask);
	}
	
	public static boolean isInNetwork(String net, long ip){
		
		String[] data = net.split("/");
		int mask = Integer.parseInt(data[1]);
		long networkLongVal = IPUtils.convertIpToNumber(data[0])>>(32-mask);
		return (ip >> (32 - mask)) == networkLongVal;
		
	}
	
	public static boolean isInNetwork(String net, String ip) {
		String[] data = net.split("/");
		long networkLongVal;
		BigInteger networkBigInt;
		long[] network;
		int mask = Integer.parseInt(data[1]);
		if (!isIpv6(ip)) {
			networkLongVal = IPUtils.convertIpToNumber(data[0])>>(32-mask);
			return (IPUtils.convertIpToNumber(ip) >> (32 - mask)) == networkLongVal;
		}else{
			
			network = IPUtils.ipV6ToLong(data[0]);
			long[] ipv6 = IPUtils.ipV6ToLong(ip);
			if(mask<64){
				return (ipv6[1]>>(64-mask) == network[1]>>(64-mask));
			}else{
				return (ipv6[1] == network[1]);
			}
		}
	}
	// version 32
	public static int totalIp(String ip){
		int mask = Integer.parseInt(ip.split("/")[1].trim());
		return 1 << (32-mask);
	}
	
	public static void main(String[] args) {
//		System.out.println(convertIpToNumber("115.79.52.11", true));
//		long num = convertIpToNumber("10.0.0.1");
	//	System.out.println(convertNumberToIp(getNetMask("192.168.1.1", 24)));
	//	System.out.println(longToIpv6(getNetMaskV6("2607:f0d0:1002:0051:1021:2210:0010:0004", 54)));
//		System.out.println(convertNumberToIp(40026810l, false));
//		System.out.println(convertIpToNumber("2.98.194.186"));
	//	System.out.println(isInNetwork("2607:f0d0:2002:1051:0000:0000:0000:0000/48","2607:f0d0:2002:0051:1021:2210:0010:0004"));
//		System.out.println(isIpv6("115.79.52.11"));
//		System.out.println(numberToIPv6((new BigInteger("50551894180553405835757616521781706756"))));
		System.out.println(IPUtils.convertNumberToIp(2946331020l));
		System.out.println(totalIp("192.168.3.1/22"));
		System.out.println(isInNetwork("192.168.1.0/24", IPUtils.convertIpToNumber("192.168.1.1")));
	}
}
