package org.cboard.security.cvicse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alibaba.fastjson.JSONObject;
import org.cboard.dto.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 校验token是否有效并解析对应的user
 */
public class JwtAuthorizationFilter extends OncePerRequestFilter {


	private static final Logger log = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

	private String signingKey;
	private String mode;

	@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {
    	try {
	    	Authentication authentication = getAuthentication(request);
	        if (authentication == null) {
	            filterChain.doFilter(request, response);
	            return;
	        }
	        SecurityContextHolder.getContext().setAuthentication(authentication);
	        filterChain.doFilter(request, response);
    	} catch (AuthenticationException failed) {
			SecurityContextHolder.clearContext();
			throw new ServletException(failed);
		}
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(SecurityConstants.TOKEN_HEADER);
        String userId = null;
        String loginName = null;
        if(SecurityConstants.MODE_TYPE_DEVELOPMENT.equals(this.getMode())) {
            userId = "1";
            loginName = "admin";
        }  else if (token != null && token.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            try {

                Jws<Claims> parsedToken = Jwts.parser()
                    .setSigningKey(this.getSigningKey())
                    .parseClaimsJws(token.replace("Bearer ", ""));
                String subject = parsedToken.getBody().getSubject();
                JSONObject userObject = JSONObject.parseObject(subject);
                userId = userObject.getString("id");
                loginName=userObject.getString("loginName");

            } catch (ExpiredJwtException exception) {
                log.warn("Request to parse expired JWT : {} failed : {}", token, exception.getMessage());
                throw new CredentialsExpiredException("token expired");
            } catch (UnsupportedJwtException exception) {
                log.warn("Request to parse unsupported JWT : {} failed : {}", token, exception.getMessage());
            } catch (MalformedJwtException exception) {
                log.warn("Request to parse invalid JWT : {} failed : {}", token, exception.getMessage());
            } catch (IllegalArgumentException exception) {
                log.warn("Request to parse empty or null JWT : {} failed : {}", token, exception.getMessage());
            }
        }

        if (userId != null) {
            List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
            authorities.add( new SimpleGrantedAuthority("ROLE_USER"));
            User user = new User(loginName,"",authorities);
            user.setUserId(userId);
            return new UsernamePasswordAuthenticationToken(user, null, authorities);
        }
        return null;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(String signingKey) {
        this.signingKey = signingKey;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    class SecurityConstants {

        // Signing key for HS512 algorithm
        // You can use the page http://www.allkeysgenerator.com/ to generate all kinds of keys

        // JWT token defaults
        public static final String TOKEN_HEADER = "Authorization";
        public static final String TOKEN_PREFIX = "Bearer ";
        public static final String TOKEN_TYPE = "JWT";
        public static final String MODE_TYPE_DEVELOPMENT = "development";
    }
}

