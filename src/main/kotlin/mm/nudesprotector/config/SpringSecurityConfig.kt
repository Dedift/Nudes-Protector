package mm.nudesprotector.config

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import mm.nudesprotector.security.LoginAttemptService
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.web.util.UriComponentsBuilder

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SpringSecurityConfig(
    @Value($$"${app.frontend.base-url:http://localhost:3000}")
    private val frontendBaseUrl: String,
    private val loginAttemptService: LoginAttemptService,
) {

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        userDetailsService: UserDetailsService,
    ): SecurityFilterChain =
        http
            .userDetailsService(userDetailsService)
            .cors(Customizer.withDefaults())
            .csrf { it.disable() }
            .authorizeHttpRequests {
                it.requestMatchers(
                    "/login",
                    "/logout",
                    "/users/register",
                    "/users/verify-email",
                    "/users/mfa/login",
                    "/users/mfa/verify",
                ).permitAll()
                it.anyRequest().authenticated()
            }
            .formLogin {
                it.successHandler(authenticationSuccessHandler())
                it.failureHandler(authenticationFailureHandler())
            }
            .logout {
                it.logoutSuccessHandler(logoutSuccessHandler())
            }
            .build()

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder(12)

    @Bean
    fun authenticationSuccessHandler(): AuthenticationSuccessHandler =
        AuthenticationSuccessHandler { _, response, authentication ->
            loginAttemptService.resetFailures(authentication.name)
            response.sendRedirect("${frontendBaseUrl.trimEnd('/')}/?screen=gallery")
        }

    @Bean
    fun authenticationFailureHandler(): AuthenticationFailureHandler =
        AuthenticationFailureHandler { request, response, exception ->
            when (exception) {
                is LockedException -> redirectWithError(response, "account_locked")
                is DisabledException -> redirectWithError(response, "email_not_verified")
                is BadCredentialsException -> {
                    val submittedEmail = submittedEmail(request)
                    val outcome = submittedEmail?.let(loginAttemptService::registerFailure)
                    if (outcome?.locked == true) {
                        redirectWithError(response, "account_locked")
                    } else {
                        redirectWithError(response, "bad_credentials")
                    }
                }
                else -> redirectWithError(response, "bad_credentials")
            }
        }

    @Bean
    fun logoutSuccessHandler(): LogoutSuccessHandler =
        LogoutSuccessHandler { _, response, _ ->
            response.sendRedirect("${frontendBaseUrl.trimEnd('/')}/?screen=login&logout=true")
        }

    private fun redirectWithError(
        response: HttpServletResponse,
        error: String,
    ) {
        val target = UriComponentsBuilder
            .fromUriString("${frontendBaseUrl.trimEnd('/')}/")
            .queryParam("screen", "login")
            .queryParam("error", error)
            .build(true)
            .toUri()

        response.status = HttpStatus.FOUND.value()
        response.setHeader("Location", target.toString())
    }

    private fun submittedEmail(request: HttpServletRequest): String? =
        request.getParameter("username")?.trim()?.lowercase()
}
