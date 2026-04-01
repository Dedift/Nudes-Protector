package mm.nudesprotector.service

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpSession
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
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class MfaAuthenticationService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val loginAttemptService: LoginAttemptService,
    private val mfaOtpService: MfaOtpService,
    private val mailService: MailService,
    private val userDetailsService: UserDetailsService,
) {
    fun startChallenge(request: MfaLoginRequest, servletRequest: HttpServletRequest): MfaChallengeResponse {
        val email = requireNotNull(request.email).trim().lowercase()
        val rawPassword = requireNotNull(request.password)
        val user = userRepository.findByEmailIgnoreCase(email) ?: handleBadCredentials(email)

        when {
            loginAttemptService.isLocked(user.email) -> throw LockedException("Account is locked")
            !user.emailVerified -> throw DisabledException("Email is not verified")
            !passwordEncoder.matches(rawPassword, user.passwordHash) -> handleBadCredentials(email)
        }

        return issueChallenge(checkNotNull(user.id), user.email, servletRequest)
    }

    fun verifyChallenge(request: MfaVerifyRequest, servletRequest: HttpServletRequest): MfaVerifyResponse {
        val code = requireNotNull(request.code).trim()
        val session = servletRequest.getSession(false)
            ?: throw IllegalArgumentException("MFA challenge not found")
        val userId = session.getAttribute(PENDING_MFA_USER_ID) as? String
        val email = session.getAttribute(PENDING_MFA_EMAIL) as? String

        if (userId == null || email == null) {
            throw IllegalArgumentException("MFA challenge not found")
        }

        val parsedUserId = UUID.fromString(userId)
        return when (mfaOtpService.verify(parsedUserId, code)) {
            MfaVerificationResult.SUCCESS -> {
                completeAuthentication(email, servletRequest)
                clearPending(session)
                MfaVerifyResponse(true, "MFA completed successfully")
            }

            MfaVerificationResult.INVALID ->
                throw IllegalArgumentException("Invalid OTP code")

            MfaVerificationResult.EXPIRED ->
                throw IllegalArgumentException("OTP code expired")

            MfaVerificationResult.REISSUE_REQUIRED -> {
                val newCode = mfaOtpService.issueOtp(parsedUserId)
                sendMfaOtp(email, newCode)
                MfaVerifyResponse(false, "Too many incorrect attempts. A new OTP code was sent")
            }
        }
    }

    private fun completeAuthentication(email: String, servletRequest: HttpServletRequest) {
        val userDetails = userDetailsService.loadUserByUsername(email)
        val authentication = UsernamePasswordAuthenticationToken.authenticated(
            userDetails,
            null,
            userDetails.authorities,
        )
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = authentication
        SecurityContextHolder.setContext(context)
        servletRequest.session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            context,
        )
    }

    private fun issueChallenge(userId: UUID, email: String, servletRequest: HttpServletRequest): MfaChallengeResponse {
        val code = mfaOtpService.issueOtp(userId)
        sendMfaOtp(email, code)
        val session = servletRequest.getSession(true)
        session.setAttribute(PENDING_MFA_USER_ID, userId.toString())
        session.setAttribute(PENDING_MFA_EMAIL, email)
        loginAttemptService.resetFailures(email)
        return MfaChallengeResponse(
            challengeStarted = true,
            message = "OTP code sent to email",
        )
    }

    private fun sendMfaOtp(email: String, code: String) {
        mailService.sendTextMail(
            email = email,
            subject = "Your MFA code",
            text = "Your one-time MFA code is: $code",
        )
    }

    private fun clearPending(session: HttpSession) {
        session.removeAttribute(PENDING_MFA_USER_ID)
        session.removeAttribute(PENDING_MFA_EMAIL)
    }

    private fun handleBadCredentials(email: String): Nothing {
        val outcome = loginAttemptService.registerFailure(email)
        if (outcome.locked) {
            throw LockedException("Account is locked")
        }
        throw IllegalArgumentException("Invalid email or password")
    }

    companion object {
        private const val PENDING_MFA_USER_ID = "pending_mfa_user_id"
        private const val PENDING_MFA_EMAIL = "pending_mfa_email"
    }
}
