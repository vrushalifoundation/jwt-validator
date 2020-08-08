package org.vrushali.jwtvalidator.util;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Component;
import org.vrushali.jwtvalidator.exception.JwtValidationException;

import lombok.extern.slf4j.Slf4j;

/**
 * This <tt>PemUtils</tt> is utility class,which will fetch the public key from
 * file
 * 
 * @author nayab
 * 
 * @since 1.0
 *
 */

@Component
@Slf4j
public class PemUtils {

	private PemUtils() {

	}

	/**
	 * The method <tt>getPublickey</tt> will return valid RSA public key from the
	 * path specified in the parameter
	 * 
	 * @param path - path cannot be null
	 * @return {@link RSAPublicKey}
	 */
	public static RSAPublicKey getPublickey(String path) {
		File f = new File(path);
		// this will make ensure no need to close resources in finally block , hence
		// this is autocloseble

		try (FileInputStream fis = new FileInputStream(f); DataInputStream dis = new DataInputStream(fis);) {
		
			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			String publicKeyContent = new String(keyBytes);
			publicKeyContent = publicKeyContent.replaceAll("\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
					.replace("-----END PUBLIC KEY-----", "");

			KeyFactory kf = KeyFactory.getInstance("RSA");

			X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));

			return (RSAPublicKey) kf.generatePublic(keySpecX509);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			log.error("Error occured in getting valid public ", e.getMessage());
			throw new JwtValidationException("Error occured in getting valid public key");
		}

	}

}
