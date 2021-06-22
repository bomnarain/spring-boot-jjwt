package kr.co.ggoom.jjwt.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
	
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
		logger.debug("403");
		//필요한 권한이 없이 접근하려 할때 403
		response.sendError(HttpServletResponse.SC_FORBIDDEN);
	}
	
}
