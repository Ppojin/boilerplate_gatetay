package com.ppojin.gateway.gateway;

import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;

import static java.nio.charset.StandardCharsets.UTF_8;

@Component
public class TracingFilter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(new Exchange(exchange));
    }

    @Override
    public int getOrder() {
        return 1;
    }

    public static final class Exchange extends ServerWebExchangeDecorator {

        private final ServerHttpRequestDecorator requestDecorator;

        public Exchange(ServerWebExchange delegate) {
            super(delegate);
            this.requestDecorator = new Request(delegate.getRequest());
        }

        @Override
        public ServerHttpRequest getRequest() {
            return requestDecorator;
        }

        @Override
        public ServerHttpResponse getResponse() {
            return super.getResponse();
        }
    }


    @Slf4j
    public static final class Request extends ServerHttpRequestDecorator {

        @Getter
        private final OffsetDateTime timestamp = OffsetDateTime.now();
        private final StringBuilder cachedBody = new StringBuilder();

        Request(ServerHttpRequest delegate) {
            super(delegate);
        }

        @Override
        public Flux<DataBuffer> getBody() {
            return super.getBody().doOnNext(this::cache);
        }

        @SneakyThrows
        private void cache(DataBuffer buffer) {
            cachedBody.append(UTF_8.decode(buffer.asByteBuffer())
                    .toString());
        }

        public String getCachedBody() {
            return cachedBody.toString();
        }
    }
}
