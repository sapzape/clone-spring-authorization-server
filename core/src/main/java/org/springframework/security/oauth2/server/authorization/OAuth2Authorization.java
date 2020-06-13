package org.springframework.security.oauth2.server.authorization;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

public class OAuth2Authorization {
	private String registeredClientId;
	private String principalName;
	private OAuth2AccessToken accessToken;
	private Map<String, Object> attributes;

	protected OAuth2Authorization() {
	}

	public String getRegisteredClientId() {
		return this.registeredClientId;
	}

	public String getPrincipalName() {
		return this.principalName;
	}

	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}

	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	public <T> T getAttribute(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) this.attributes.get(name);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		OAuth2Authorization that = (OAuth2Authorization) o;
		return Objects.equals(this.registeredClientId, that.registeredClientId) &&
				Objects.equals(this.principalName, that.principalName) &&
				Objects.equals(this.accessToken, that.accessToken) &&
				Objects.equals(this.attributes, that.attributes);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.registeredClientId, this.principalName, this.accessToken, this.attributes);
	}

	public static Builder builder() {
		return new Builder();
	}

	public static Builder withAuthorization(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		return new Builder(authorization);
	}

	public static class Builder {
		private String registeredClientId;
		private String principalName;
		private OAuth2AccessToken accessToken;
		private Map<String, Object> attributes = new HashMap<>();

		protected Builder() {
		}

		protected Builder(OAuth2Authorization authorization) {
			this.registeredClientId = authorization.registeredClientId;
			this.principalName = authorization.principalName;
			this.accessToken = authorization.accessToken;
			this.attributes = authorization.attributes;
		}

		public Builder registeredClientId(String registeredClientId) {
			this.registeredClientId = registeredClientId;
			return this;
		}

		public Builder principalName(String principalName) {
			this.principalName = principalName;
			return this;
		}

		public Builder accessToken(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			return this;
		}

		public Builder attribute(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.hasText(value, "value cannot be empty");
			this.attributes.put(name, value);
			return this;
		}

		public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
			attributesConsumer.accept(this.attributes);
			return this;
		}

		public OAuth2Authorization build() {
			Assert.hasText(this.registeredClientId, "registeredClientId cannot be empty");
			Assert.hasText(this.principalName, "principalName cannot be empty");
			if (this.accessToken == null && this.attributes.get(TokenType.AUTHORIZATION_CODE.getValue()) == null) {
				throw new IllegalArgumentException("either accessToken has to be set or the authorization code with key '"
						+ TokenType.AUTHORIZATION_CODE.getValue() + "' must be provided in the attributes map");
			}
			return create();
		}

		private OAuth2Authorization create() {
			OAuth2Authorization oAuth2Authorization = new OAuth2Authorization();
			oAuth2Authorization.registeredClientId = this.registeredClientId;
			oAuth2Authorization.principalName = this.principalName;
			oAuth2Authorization.accessToken = this.accessToken;
			oAuth2Authorization.attributes = Collections.unmodifiableMap(this.attributes);
			return oAuth2Authorization;
		}
	}
}
