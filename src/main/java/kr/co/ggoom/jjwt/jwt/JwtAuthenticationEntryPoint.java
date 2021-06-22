package kr.co.ggoom.jjwt.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 유효한 자격증명을 제공하지 않고 접근하려 할때 401 Unauthorized 에러를 리턴
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
	
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	
   @Override
   public void commence(HttpServletRequest request,
                        HttpServletResponse response,
                        AuthenticationException authException) throws IOException {
      // 유효한 자격증명을 제공하지 않고 접근하려 할때 401
	   logger.debug("JwtAuthenticationEntryPoint : 401");
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
   }
}

