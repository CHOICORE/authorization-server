package me.choicore.samples.authorization

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.web.session.HttpSessionEventPublisher

@Configuration(proxyBeanMethods = false)
class HttpSessionConfiguration {
    @Bean
    fun springSessionDefaultRedisSerializer(objectMapper: ObjectMapper): RedisSerializer<Any> =
        GenericJackson2JsonRedisSerializer(objectMapper)

    @Bean
    fun httpSessionEventPublisher(): HttpSessionEventPublisher = HttpSessionEventPublisher()
}
