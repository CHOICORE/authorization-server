package me.choicore.samples.authorization

import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module

@Configuration(proxyBeanMethods = false)
class Jackson2ObjectMapperConfiguration {
    @Bean
    fun oauthAuthorizationServerJackson2ObjectMapperBuilderCustomizer(): Jackson2ObjectMapperBuilderCustomizer =
        Jackson2ObjectMapperBuilderCustomizer { builder ->
            builder.modules { modules ->
                modules.add(OAuth2AuthorizationServerJackson2Module())
            }
        }

    @Bean
    fun securityJackson2ModulesJackson2ObjectMapperBuilderCustomizer(): Jackson2ObjectMapperBuilderCustomizer =
        Jackson2ObjectMapperBuilderCustomizer { builder ->
            builder.modules { modules ->
                modules.addAll(SecurityJackson2Modules.getModules(ClassLoader.getSystemClassLoader()))
            }
        }
}
