package mm.nudesprotector.config

import mm.nudesprotector.security.LoginAttemptService
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class SpringSecurityConfig(
    @Value($$"${app.frontend.base-url:http://localhost:3000}")
    private val frontendBaseUrl: String,
    private val loginAttemptService: LoginAttemptService,
) {

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain =
        http
            .cors(Customizer.withDefaults())
            .csrf { it.disable() }
            .authorizeExchange {
                it.pathMatchers(
                    "/login",
                    "/logout",
                    "/users/register",
                    "/users/verify-email",
                    ).permitAll()
                it.anyExchange().authenticated()
            }
            .formLogin {
                it.authenticationSuccessHandler(authenticationSuccessHandler())
                it.authenticationFailureHandler(authenticationFailureHandler())
            }
            .logout {
                it.logoutSuccessHandler(logoutSuccessHandler())
            }
            .build()

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder(12)

    @Bean
    fun reactiveAuthenticationManager(
        reactiveUserDetailsService: ReactiveUserDetailsService,
        passwordEncoder: PasswordEncoder,
    ): ReactiveAuthenticationManager =
        UserDetailsRepositoryReactiveAuthenticationManager(reactiveUserDetailsService).apply {
            setPasswordEncoder(passwordEncoder)
        }

    @Bean
    fun authenticationSuccessHandler(): ServerAuthenticationSuccessHandler =
        ServerAuthenticationSuccessHandler { webFilterExchange, authentication ->
            loginAttemptService.resetFailures(authentication.name)
                .then(
                    RedirectServerAuthenticationSuccessHandler(
                        "${frontendBaseUrl.trimEnd('/')}/?screen=gallery",
                    ).onAuthenticationSuccess(webFilterExchange, authentication),
                )
        }

    @Bean
    fun authenticationFailureHandler(): ServerAuthenticationFailureHandler =
        ServerAuthenticationFailureHandler { webFilterExchange, exception ->
            when (exception) {
                is LockedException -> redirectWithError(webFilterExchange, "account_locked")
                is DisabledException -> redirectWithError(webFilterExchange, "email_not_verified")
                is BadCredentialsException -> {
                    submittedEmail(webFilterExchange.exchange)
                        .flatMap { email -> loginAttemptService.registerFailure(email) }
                        .flatMap { outcome ->
                            if (outcome.locked) {
                                redirectWithError(webFilterExchange, "account_locked")
                            } else {
                                redirectWithError(webFilterExchange, "bad_credentials")
                            }
                        }
                }
                else -> redirectWithError(webFilterExchange, "bad_credentials")
            }
        }

    @Bean
    fun logoutSuccessHandler(): RedirectServerLogoutSuccessHandler =
        RedirectServerLogoutSuccessHandler().apply {
            setLogoutSuccessUrl(URI.create("${frontendBaseUrl.trimEnd('/')}/?screen=login&logout=true"))
        }

    private fun redirectWithError(
        webFilterExchange: WebFilterExchange,
        error: String,
    ): Mono<Void> {
        val target = UriComponentsBuilder
            .fromUriString("${frontendBaseUrl.trimEnd('/')}/")
            .queryParam("screen", "login")
            .queryParam("error", error)
            .build(true)
            .toUri()

        webFilterExchange.exchange.response.statusCode = HttpStatus.FOUND
        webFilterExchange.exchange.response.headers.location = target
        return webFilterExchange.exchange.response.setComplete()
    }

    private fun submittedEmail(exchange: ServerWebExchange): Mono<String> =
        exchange.formData
            .mapNotNull { it.getFirst("username")?.trim()?.lowercase() }
}
