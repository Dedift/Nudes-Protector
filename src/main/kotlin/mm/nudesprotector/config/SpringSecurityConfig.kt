package mm.nudesprotector.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
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
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class SpringSecurityConfig(
    @Value($$"${app.frontend.base-url:http://localhost:3000}")
    private val frontendBaseUrl: String,
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
    fun authenticationSuccessHandler(): RedirectServerAuthenticationSuccessHandler =
        RedirectServerAuthenticationSuccessHandler(
            "${frontendBaseUrl.trimEnd('/')}/?screen=gallery",
        )

    @Bean
    fun authenticationFailureHandler(): ServerAuthenticationFailureHandler =
        ServerAuthenticationFailureHandler { webFilterExchange, _ ->

            val target = UriComponentsBuilder
                .fromUriString("${frontendBaseUrl.trimEnd('/')}/")
                .queryParam("screen", "login")
                .queryParam("error", "login_failed")
                .build(true)
                .toUri()

            webFilterExchange.exchange.response.statusCode = HttpStatus.FOUND
            webFilterExchange.exchange.response.headers.location = target
            webFilterExchange.exchange.response.setComplete()
        }

    @Bean
    fun logoutSuccessHandler(): RedirectServerLogoutSuccessHandler =
        RedirectServerLogoutSuccessHandler().apply {
            setLogoutSuccessUrl(URI.create("${frontendBaseUrl.trimEnd('/')}/?screen=login&logout=true"))
        }
}
