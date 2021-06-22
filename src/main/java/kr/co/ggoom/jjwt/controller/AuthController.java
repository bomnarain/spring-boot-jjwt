package kr.co.ggoom.jjwt.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import kr.co.ggoom.jjwt.dto.LoginDto;
import kr.co.ggoom.jjwt.dto.TokenDto;
import kr.co.ggoom.jjwt.jwt.JwtAuthenticationFilter;
import kr.co.ggoom.jjwt.jwt.JwtTokenProvider;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(JwtTokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
    	logger.debug("authenticate : {} / {}", loginDto.getUsername(), loginDto.getPassword());
    	// 사용자 확인
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        logger.debug("authenticationToken: {}", authenticationToken.toString());        
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        logger.debug("authentication: {}", authentication.toString());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 토큰 생성
        String jwt = tokenProvider.createToken(authentication, false);
        
        logger.debug("jwt : {}", jwt);
        
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtAuthenticationFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}

