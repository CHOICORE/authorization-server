package me.choicore.samples.authorization

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.RSAKey.Builder
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.autoconfigure.security.servlet.PathRequest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationEventPublisher
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class WebSecurityConfiguration {
    @Configuration(proxyBeanMethods = false)
    class DefaultSecurityConfiguration {
        @Bean
        @Order(Ordered.LOWEST_PRECEDENCE)
        @Throws(Exception::class)
        fun defaultSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain =
            httpSecurity
                .csrf {
                    it.disable()
                }.authorizeHttpRequests { authorizeHttpRequests ->
                    authorizeHttpRequests
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                        .permitAll()
                        .requestMatchers("/sign-in", "/error/**")
                        .permitAll()
                    authorizeHttpRequests
                        .anyRequest()
                        .authenticated()
                }.formLogin { formLogin ->
                    formLogin.loginPage("/sign-in")
                    formLogin.loginProcessingUrl("/sign-in")
                }.logout { logout -> logout.logoutUrl("/sign-out") }
                .build()

        @Bean
        fun userDetailsService(): UserDetailsService {
            val user: UserDetails =
                User
                    .builder()
                    .username("1")
                    .password("{noop}1")
                    .roles("USER")
                    .build()

            return InMemoryUserDetailsManager(user)
        }

        @Bean
        fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

        @Bean
        fun authenticationEventPublisher(): AuthenticationEventPublisher = DefaultAuthenticationEventPublisher()
    }

    @Configuration(proxyBeanMethods = false)
    class OAuthAuthorizationServerSecurityConfiguration {
        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        @Throws(Exception::class)
        fun authorizationServerSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain {
            val authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer()
            httpSecurity
                .securityMatcher(authorizationServerConfigurer.endpointsMatcher)
                .with(authorizationServerConfigurer) { authorizationServer ->
                    authorizationServer
                        .oidc(Customizer.withDefaults())
                }.authorizeHttpRequests {
                    it.anyRequest().authenticated()
                }.exceptionHandling { exceptionHandling ->
                    exceptionHandling
                        .defaultAuthenticationEntryPointFor(
                            LoginUrlAuthenticationEntryPoint("/sign-in"),
                            MediaTypeRequestMatcher(MediaType.TEXT_HTML),
                        )
                }

            return httpSecurity.build()
        }

        @Bean
        fun jwkSource(): JWKSource<SecurityContext> {
            val keyPair: KeyPair = generateRsaKey()
            val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
            val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
            val rsaKey: RSAKey =
                Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build()
            return ImmutableJWKSet(JWKSet(rsaKey))
        }

        private fun generateRsaKey(): KeyPair {
            val keyPair: KeyPair
            try {
                val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                keyPair = keyPairGenerator.generateKeyPair()
            } catch (ex: java.lang.Exception) {
                throw IllegalStateException(ex)
            }
            return keyPair
        }

        @Bean
        fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

        @Bean
        fun authorizationServerSettings(): AuthorizationServerSettings = AuthorizationServerSettings.builder().build()
    }
}
