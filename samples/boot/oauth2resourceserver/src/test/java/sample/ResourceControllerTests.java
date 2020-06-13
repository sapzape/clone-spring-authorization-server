package sample;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
public class ResourceControllerTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void shouldReturnOkWithToken() throws Exception {
		this.mockMvc.perform(get("/").header("Authorization", "Bearer TOKEN"))
				.andExpect(status().isOk());
	}

	@Test
	public void shouldReturnUnauthorizedWithoutToken() throws Exception {
		this.mockMvc.perform(get("/"))
				.andExpect(status().isUnauthorized());
	}

	@TestConfiguration
	static class ResourceControllerTestConfiguration {
		@Bean
		public JwtDecoder jwtDecoder() {
			return (token) -> {
				Map<String, Object> headers = new HashMap<>();
				headers.put("alg", "RS256");
				headers.put("typ", "JWT");

				Map<String, Object> claims = new HashMap<>();
				claims.put("sub", "1234567");
				claims.put("name", "John Doe");
				return new Jwt(token, Instant.now(), Instant.now().plusMillis(5000), headers, claims);
			};
		}
	}
}
