package com.ppojin.gateway.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class code {
    @GetMapping("/auth/**")
    ResponseEntity<String> codeToJwt(
            @RequestParam("code") String code,
            @RequestParam("session_state") String redirectUri,
            ServerHttpRequest request
    ){
        RequestPath path = request.getPath();

        log.info("{}", path);

        return ResponseEntity.ok().headers(h->{
            h.add("Set-Cookie", "X-REFRESH-TOKEN=asdf");
            h.add("X-refresh-token", "asdf");
        }).build();
    }
}
