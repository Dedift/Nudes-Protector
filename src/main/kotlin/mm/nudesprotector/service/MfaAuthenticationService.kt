package mm.nudesprotector.service

import mm.nudesprotector.domain.dto.request.MfaLoginRequest
import mm.nudesprotector.domain.dto.request.MfaVerifyRequest
import mm.nudesprotector.domain.dto.response.MfaChallengeResponse
import mm.nudesprotector.domain.dto.response.MfaVerifyResponse
import mm.nudesprotector.mail.MailService
import mm.nudesprotector.repository.UserRepository
import mm.nudesprotector.security.LoginAttemptService
import mm.nudesprotector.security.MfaOtpService
import mm.nudesprotector.security.MfaVerificationResult
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.stereotype.Service
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.util.UUID

@Service
class MfaAuthenticationService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val loginAttemptService: LoginAttemptService,
    private val mfaOtpService: MfaOtpService,
    private val mailService: MailService,
    private val reactiveUserDetailsService: ReactiveUserDetailsService,
) {
    private val securityContextRepository = WebSessionServerSecurityContextRepository()

    fun startChallenge(request: MfaLoginRequest, exchange: ServerWebExchange): Mono<MfaChallengeResponse> {
        val email = requireNotNull(request.email).trim()
        val rawPassword = requireNotNull(request.password)

        return userRepository.findByEmailIgnoreCase(email)
            .switchIfEmpty(handleBadCredentials(email))
            .flatMap { user ->
                loginAttemptService.isLocked(user.email)
                    .flatMap { locked ->
                        when {
                            locked -> Mono.error(LockedException("Account is locked"))
                            !user.emailVerified -> Mono.error(DisabledException("Email is not verified"))
                            else -> Mono.fromCallable { passwordEncoder.matches(rawPassword, user.passwordHash) }
                                .subscribeOn(Schedulers.boundedElastic())
                                .flatMap { matches ->
                                    if (!matches) {
                                        handleBadCredentials(email)
                                    } else {
                                        issueChallenge(checkNotNull(user.id), user.email, exchange)
                                    }
                                }
                        }
                    }
            }
    }

    fun verifyChallenge(request: MfaVerifyRequest, exchange: ServerWebExchange): Mono<MfaVerifyResponse> {
        val code = requireNotNull(request.code).trim()

        return exchange.session.flatMap { session ->
            val userId = session.attributes[PENDING_MFA_USER_ID] as? String
            val email = session.attributes[PENDING_MFA_EMAIL] as? String

            if (userId == null || email == null) {
                return@flatMap Mono.error(IllegalArgumentException("MFA challenge not found"))
            }

            val parsedUserId = UUID.fromString(userId)
            mfaOtpService.verify(parsedUserId, code)
                .flatMap { result ->
                    when (result) {
                        MfaVerificationResult.SUCCESS -> completeAuthentication(email, exchange)
                            .then(clearPending(session))
                            .thenReturn(MfaVerifyResponse(true, "MFA completed successfully"))

                        MfaVerificationResult.INVALID ->
                            Mono.error(IllegalArgumentException("Invalid OTP code"))

                        MfaVerificationResult.EXPIRED ->
                            Mono.error(IllegalArgumentException("OTP code expired"))

                        MfaVerificationResult.REISSUE_REQUIRED ->
                            mfaOtpService.issueOtp(parsedUserId)
                                .flatMap { newCode -> sendMfaOtp(email, newCode) }
                                .thenReturn(MfaVerifyResponse(false, "Too many incorrect attempts. A new OTP code was sent"))
                    }
                }
        }
    }

    private fun completeAuthentication(email: String, exchange: ServerWebExchange): Mono<Void> =
        reactiveUserDetailsService.findByUsername(email)
            .flatMap { userDetails ->
                val authentication = UsernamePasswordAuthenticationToken.authenticated(
                    userDetails,
                    null,
                    userDetails.authorities,
                )
                securityContextRepository.save(exchange, SecurityContextImpl(authentication))
            }

    private fun issueChallenge(userId: UUID, email: String, exchange: ServerWebExchange): Mono<MfaChallengeResponse> =
        mfaOtpService.issueOtp(userId)
            .flatMap { code -> sendMfaOtp(email, code) }
            .then(
                exchange.session.flatMap { session ->
                    session.attributes[PENDING_MFA_USER_ID] = userId.toString()
                    session.attributes[PENDING_MFA_EMAIL] = email
                    loginAttemptService.resetFailures(email)
                        .thenReturn(
                            MfaChallengeResponse(
                                challengeStarted = true,
                                message = "OTP code sent to email",
                            ),
                        )
                },
            )

    private fun sendMfaOtp(email: String, code: String): Mono<Void> =
        mailService.sendTextMail(
            email = email,
            subject = "Your MFA code",
            text = "Your one-time MFA code is: $code",
        )

    private fun clearPending(session: org.springframework.web.server.WebSession): Mono<Void> {
        session.attributes.remove(PENDING_MFA_USER_ID)
        session.attributes.remove(PENDING_MFA_EMAIL)
        return Mono.empty()
    }

    private fun handleBadCredentials(email: String): Mono<Nothing> =
        loginAttemptService.registerFailure(email)
            .flatMap { outcome ->
                if (outcome.locked) {
                    Mono.error(LockedException("Account is locked"))
                } else {
                    Mono.error(IllegalArgumentException("Invalid email or password"))
                }
            }

    companion object {
        private const val PENDING_MFA_USER_ID = "pending_mfa_user_id"
        private const val PENDING_MFA_EMAIL = "pending_mfa_email"
    }
}
