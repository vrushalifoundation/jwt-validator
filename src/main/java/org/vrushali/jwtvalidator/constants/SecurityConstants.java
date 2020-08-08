package org.vrushali.jwtvalidator.constants;

public final class SecurityConstants {

	private SecurityConstants() {

	}

	public static final String HEADER_AUTHORIZATION = "Authorization";
	public static final String BEARER = "Bearer ";
	public static final String SECRET_KEY = "-----BEGIN PUBLIC KEY-----\n" + 
			"MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH1IHoxOU8l6Zj2jaTZeeOIEwlGa\n" + 
			"wHnFz0rtiDeYnEwDBB7u74nv+vys8zUQrYIW4FH4Qd7PUpmpT7ILDqs53SAccE88\n" + 
			"NBXluR9g4FNLZJPrVWTuJBckPA2GFrQbPAxS2GzExumsBqKKcjmWoBb2sdNyLmI3\n" + 
			"KhIJwDCPOXu15kmdAgMBAAE=\n" + 
			"-----END PUBLIC KEY-----";

}
