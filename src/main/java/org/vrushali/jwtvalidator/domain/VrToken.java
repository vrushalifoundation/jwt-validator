package org.vrushali.jwtvalidator.domain;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONObject;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.vrushali.jwtvalidator.constants.JwtConstants;
import org.vrushali.jwtvalidator.util.PemUtils;

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
	@SuppressWarnings("unchecked")
	public static VrToken fromToken(String token) {
		JSONObject obj = new JSONObject(
				Jwts.parser().setSigningKey(PemUtils.getPublickey(JwtConstants.PUBLIC_KEY_FILE_PATH))
						.parseClaimsJws(token).getBody());

		List<String> roles1 = null;

		roles1 = (List<String>) Jwts.parser().setSigningKey(PemUtils.getPublickey(JwtConstants.PUBLIC_KEY_FILE_PATH))
				.parseClaimsJws(token).getBody().get(JwtConstants.PROFILE_ROLES);

		Set<GrantedAuthority> authorities = new HashSet<>();
		for (String role : roles1) {
			authorities.add(new SimpleGrantedAuthority(role));
		}

		return VrToken.builder().firstName(obj.getString(JwtConstants.PROFILE_FIRST_NAME))
				.lastName(obj.getString(JwtConstants.PROFILE_LAST_NAME))
				.email(obj.getString(JwtConstants.PROFILE_EMAIL)).roles(authorities).build();
	}

}
