package br.com.avelar.api.oauth;

import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.ext.Provider;

import br.com.avelar.backend.model.OAuthToken;
import br.com.avelar.backend.service.OAuthTokenService;

@Provider
@PreMatching
public class OAuthFilter implements ContainerRequestFilter {

    @Inject
    private OAuthTokenService oAuthService;

    @Override
    public void filter(ContainerRequestContext ctx) {
        if(!ctx.getUriInfo().getPath().equals("/token")) {
            String authHeader = ctx.getHeaderString("oauth_token");
            
            if (authHeader == null) {
                throw new NotAuthorizedException("Bearer");
            }

            OAuthToken token = oAuthService.getTokenInfo(authHeader);

            if(token == null) {
                throw new NotAuthorizedException("Invalid bearer token");
            }

            if(!token.valid()) {
                oAuthService.revokeToken(token.getToken());
                throw new NotAuthorizedException("Token has expired or user is inactive");
            }
        }
    }

}
