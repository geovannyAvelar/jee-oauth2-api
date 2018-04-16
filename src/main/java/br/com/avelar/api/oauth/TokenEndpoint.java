package br.com.avelar.api.oauth;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.mindrot.jbcrypt.BCrypt;

import br.com.avelar.backend.model.OAuthToken;
import br.com.avelar.backend.model.User;
import br.com.avelar.backend.service.OAuthTokenService;
import br.com.avelar.backend.service.UserService;

@Path("/token")
public class TokenEndpoint {

    private User user;

    @Inject
    private UserService userService;
    
    @Inject
    private OAuthTokenService oauthService;

    public static final String INVALID_CLIENT_DESCRIPTION = 
            "Client authentication failed (e.g., unknown client, no client authentication " + 
            "included, or unsupported authentication method).";

    @POST
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response authorize(@Context HttpServletRequest request) throws OAuthSystemException {
        try {
            OAuthTokenRequest oauthRequest = new OAuthTokenRequest(request);
            OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

            // check if clientid is valid
            if (!checkClientId(oauthRequest.getClientId())) {
                return buildInvalidClientIdResponse();
            }

            // check if client_secret is valid
            if (!checkClientSecret(oauthRequest.getClientSecret())) {
                return buildInvalidClientSecretResponse();
            }

            // do checking for different grant types
            if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE)
                                            .equals(GrantType.AUTHORIZATION_CODE.toString())) {
                return buildBadAuthCodeResponse();
            } 
            
            if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE).equals(GrantType.PASSWORD.toString())
                    && !checkUserPass(oauthRequest.getUsername(), oauthRequest.getPassword())) {
                return buildInvalidUserPassResponse();
            }
                
            if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE)
                                                    .equals(GrantType.REFRESH_TOKEN.toString())) {
                // refresh token is not supported in this implementation
                buildInvalidUserPassResponse();
            }

            OAuthToken userToken = oauthService.getTokenByUser(user);

            // User already have a valid token
            if(userToken != null && userToken.valid()) {
                OAuthResponse response = OAuthASResponse
                        .tokenResponse(HttpServletResponse.SC_OK)
                        .setAccessToken(userToken.getToken())
                        .setExpiresIn(userToken.getTimeToExpire().toString())
                        .buildJSONMessage();
                return Response.status(response.getResponseStatus())
                               .entity(response.getBody())
                               .build();
            }
            
            final String accessToken = oauthIssuerImpl.accessToken();
            oauthService.registerToken(accessToken, user);
            
            OAuthResponse response = OAuthASResponse
                    .tokenResponse(HttpServletResponse.SC_OK)
                    .setAccessToken(accessToken)
                    .setExpiresIn("1200")
                    .buildJSONMessage();
            return Response.status(response.getResponseStatus())
                           .entity(response.getBody())
                           .build();
            
        } catch (OAuthProblemException e) {
            OAuthResponse res = 
                    OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                                                                    .error(e).buildJSONMessage();
            return Response.status(res.getResponseStatus()).entity(res.getBody()).build();
        }
    }

    private Response buildInvalidClientIdResponse() throws OAuthSystemException {
        OAuthResponse response =
                OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.TokenResponse.INVALID_CLIENT)
                .setErrorDescription(INVALID_CLIENT_DESCRIPTION)
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private Response buildInvalidClientSecretResponse() throws OAuthSystemException {
        OAuthResponse response =
                OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                .setError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT)
                .setErrorDescription(INVALID_CLIENT_DESCRIPTION)
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private Response buildBadAuthCodeResponse() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.TokenResponse.INVALID_GRANT)
                .setErrorDescription("invalid authorization code")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private Response buildInvalidUserPassResponse() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.TokenResponse.INVALID_GRANT)
                .setErrorDescription("invalid username or password")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private boolean checkClientId(String clientId) {
        return true;
    }

    private boolean checkClientSecret(String secret) {
        return true;
    }

    private boolean checkUserPass(String username, String password) {
        user = userService.findUserByUsername(username);
        return user != null && BCrypt.checkpw(password, user.getPassword());
    }

}
