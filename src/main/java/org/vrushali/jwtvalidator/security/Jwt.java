package org.vrushali.jwtvalidator.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.vrushali.jwtvalidator.constants.JwtConstants;
import org.vrushali.jwtvalidator.constants.SecurityConstants;
import org.vrushali.jwtvalidator.domain.VrToken;
import org.vrushali.jwtvalidator.util.PemUtils;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

/**
 * The class <tt>Jwtfilter</tt> which extend OncePerRequestFilter class which
 * will execute only once per request dispatch
 * 
 * @author nayab
 * @see {@link OncePerRequestFilter}}
 * @since 1.0
 *
 */

@Slf4j
public final class Jwt  {

	

	public void authenticate(HttpServletRequest request) {
		log.debug("Validating Token");
		String token = resolveToken(request);
		try {
			if (token != null && validateToken(token)) {
				log.info("Token is valid");
				Authentication auth = getAuthentication(token);
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		} catch (Exception ex) {
			// this is very important, since it guarantees the user is not authenticated at
			// all
			log.debug("exception occurred while validating", ex.getMessage());
			SecurityContextHolder.clearContext();
			return;
		}
	}

	/**
	 * The method <tt>getAuthentication</tt> which parse the token to object and set
	 * the object and roles in UsernamePasswordAuthenticationToken
	 * 
	 * @param token - token must not be null
	 * @return
	 */
	private Authentication getAuthentication(String token) {
		VrToken vRtoken = VrToken.fromToken(token);
		return new UsernamePasswordAuthenticationToken(vRtoken, null, vRtoken.getRoles());
	}

	/**
	 * The method <tt>resolveToken</tt> will extract the token from
	 * {@link HttpServletRequest} object.
	 * 
	 * @see {@link HttpServletRequest}
	 * @param request
	 * @return
	 */
	private String resolveToken(HttpServletRequest request) {
		String bearerToken = request.getHeader(SecurityConstants.HEADER_AUTHORIZATION);
		if (bearerToken != null && bearerToken.startsWith(SecurityConstants.BEARER)) {
			return bearerToken.substring(7);
		}
		return null;
	}

	/**
	 * The method <tt>validateToken</tt> will validate the token with secret key.
	 * 
	 * @param token
	 * @return
	 */
	private boolean validateToken(String token) {
		try {
			Jwts.parser().setSigningKey(PemUtils.getPublickey(JwtConstants.PUBLIC_KEY_FILE_PATH)).parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			log.error("invalid token",e.getMessage());
			e.printStackTrace();
			throw new JwtException(e.getMessage());
		}
	}

}
