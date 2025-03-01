package me.choicore.samples.authorization

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.BeanClassLoaderAware
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.web.session.HttpSessionEventPublisher

@Configuration(proxyBeanMethods = false)
class SessionConfiguration : BeanClassLoaderAware {
    private lateinit var classLoader: ClassLoader

    override fun setBeanClassLoader(classLoader: ClassLoader) {
        this.classLoader = classLoader
    }

    @Bean
    fun springSessionDefaultRedisSerializer(objectMapper: ObjectMapper): RedisSerializer<Any> {
        val copied: ObjectMapper = objectMapper.copy()
        copied.registerModules(SecurityJackson2Modules.getModules(this.classLoader))
        return GenericJackson2JsonRedisSerializer(copied)
    }

    @Bean
    fun httpSessionEventPublisher(): HttpSessionEventPublisher = HttpSessionEventPublisher()
}
