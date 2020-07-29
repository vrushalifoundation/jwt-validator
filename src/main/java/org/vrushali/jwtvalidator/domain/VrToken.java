package org.vrushali.jwtvalidator.domain;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONObject;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.vrushali.jwtvalidator.constants.JwtConstants;
import org.vrushali.jwtvalidator.constants.SecurityConstants;

import io.jsonwebtoken.Jwts;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public final class VrToken {
	
	private String userName;
	private String firstName;
	private String lastName;
	private String email;
	private Collection<? extends GrantedAuthority> roles;

	/**
	 * The method <tt>fromToken</tt> will give the VrToken object from string token
	 * 
	 * @param token
	 * @return
	 */
	public static VrToken fromToken(String token) {
		JSONObject obj = new JSONObject(
				Jwts.parser().setSigningKey(SecurityConstants.SECRET_KEY).parseClaimsJws(token).getBody());

		List<String> roles = (List<String>) Jwts.parser().setSigningKey(SecurityConstants.SECRET_KEY)
				.parseClaimsJws(token).getBody().get(JwtConstants.PROFILE_ROLES);
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>(roles.size());
		for (String role : roles) {
			authorities.add(new SimpleGrantedAuthority(role));
		}

		return VrToken.builder().firstName(obj.getString(JwtConstants.PROFILE_FIRST_NAME))
				.lastName(obj.getString(JwtConstants.PROFILE_LAST_NAME))
				.email(obj.getString(JwtConstants.PROFILE_ROLES)).roles(authorities).build();
	}

}
