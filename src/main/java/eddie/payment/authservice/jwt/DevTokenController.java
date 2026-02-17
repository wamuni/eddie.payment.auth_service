package eddie.payment.authservice.jwt;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

@RestController
public class DevTokenController {

	private final RSAPrivateKey privateKey;

	public DevTokenController() { this.privateKey = loadPrivateKey(); }

	@GetMapping("/token/dev")
	public Map<String, Object> token(
		@RequestParam(defaultValue = "user-1") String sub,
		@RequestParam(defaultValue = "eddie@payment.com") String email
		) throws Exception {
			Instant now = Instant.now();
			JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.issuer("http://localhost:9000")
				.subject(sub)
				.claim("email", email)
				.claim("roles", List.of("USER"))
				.issueTime(Date.from(now))
				.expirationTime(Date.from(now.plusSeconds(15 * 60)))
				.build();
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID("dev-kid-1")
				.type(JOSEObjectType.JWT)
				.build();
			SignedJWT jwt = new SignedJWT(header, claims);
			jwt.sign(new RSASSASigner(privateKey));

			return Map.of("access_token", jwt.serialize());
		}
	private RSAPrivateKey loadPrivateKey() {
		try {
			String pem = new String(new ClassPathResource("keys/jwt-private.pem").getInputStream().readAllBytes());
			String base64 = pem
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replaceAll("\\s", "");
			byte[] der = Base64.getDecoder().decode(base64);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
			return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
		} catch(Exception e) {
			throw new IllegalStateException("Failed to load private key", e);
		}
	}
}
