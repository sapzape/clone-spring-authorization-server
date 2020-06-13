package org.springframework.security.oauth2.server.authorization;

import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {
	private final List<OAuth2Authorization> authorizations;

	public InMemoryOAuth2AuthorizationService() {
		this.authorizations = new CopyOnWriteArrayList<>();
	}

	public InMemoryOAuth2AuthorizationService(List<Oauth2Authorization> authorizations) {
		Assert.notEmpty(authorizations, "authorizations cannot be empty");
		this.authorizations = new CopyOnWriteArrayList<>(authorizations);
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorizations, "authorization cannot be null");
		this.authorizations.add(authorization);
	}

	@Override
	public OAuth2Authorization findByTokenAndTokenType(String token, TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		Assert.notNull(tokenType, "tokenType cannot be null");
		return this.authorizations.stream()
				.filter(authorizations -> hasToken(authorizations, token, tokenType))
				.findFirst()
				.orElse(null);
	}


	private boolean hasToken (OAuth2Authorization authorization, String token, TokenType tokenType){
		if (TokenType.AUTHORIZATION_CODE.equals(tokenType)) {
			return token.equals(authorization.getAttributes().get(TokenType.AUTHORIZATION_CODE.getValue()));
		} else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return authorization.getAccessToken() != null &&
					authorization.getAccessToken().getTokenValue().equals(token);
		}
		return false;
	}
}
