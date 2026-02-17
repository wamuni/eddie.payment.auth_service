package eddie.payment.authservice.jwt;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.core.io.ClassPathResource;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@RestController
public class JwksController {
	private final RSAKey rsaJwk;

	public JwksController() {
		this.rsaJwk = loadPublicJwk();
	}
	
	@GetMapping("/.well-known/jwks.json")
	public Map<String, Object> jwks() {
		return new JWKSet(rsaJwk).toJSONObject();
	}

	private RSAKey loadPublicJwk() {
		try {
			String pem = new String(new ClassPathResource("keys/jwt-public.pem").getInputStream().readAllBytes());
			String base64 = pem
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");

			byte[] der = Base64.getDecoder().decode(base64);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
			RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);

			return new RSAKey.Builder(pub).keyID("dev-kid-1").build();
		} catch(Exception e) {
			throw new IllegalStateException("Failed to load public key", e);
		}
	}
}
