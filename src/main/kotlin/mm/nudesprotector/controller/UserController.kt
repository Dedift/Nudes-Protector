package mm.nudesprotector.controller

import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import mm.nudesprotector.domain.dto.request.CreateUserRequest
import mm.nudesprotector.domain.dto.request.MfaLoginRequest
import mm.nudesprotector.domain.dto.request.MfaVerifyRequest
import mm.nudesprotector.domain.dto.request.VerifyEmailRequest
import mm.nudesprotector.domain.dto.response.CreateUserResponse
import mm.nudesprotector.domain.dto.response.MfaChallengeResponse
import mm.nudesprotector.domain.dto.response.MfaVerifyResponse
import mm.nudesprotector.domain.dto.response.PasskeyResponse
import mm.nudesprotector.domain.dto.response.VerifyEmailResponse
import mm.nudesprotector.mail.EmailVerificationService
import mm.nudesprotector.service.MfaAuthenticationService
import mm.nudesprotector.service.PasskeyService
import mm.nudesprotector.service.UserRegistrationService
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserController(
    private val userRegistrationService: UserRegistrationService,
    private val emailVerificationService: EmailVerificationService,
    private val mfaAuthenticationService: MfaAuthenticationService,
    private val passkeyService: PasskeyService,
) {
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    fun createUser(@Valid @RequestBody request: CreateUserRequest): CreateUserResponse =
        userRegistrationService.createUser(request)

    @PostMapping("/verify-email")
    @ResponseStatus(HttpStatus.OK)
    fun verifyEmail(@Valid @RequestBody request: VerifyEmailRequest): VerifyEmailResponse =
        emailVerificationService.verifyEmail(request)

    @PostMapping("/mfa/login")
    @ResponseStatus(HttpStatus.OK)
    fun startMfaLogin(
        @Valid @RequestBody request: MfaLoginRequest,
        servletRequest: HttpServletRequest,
    ): MfaChallengeResponse =
        mfaAuthenticationService.startChallenge(request, servletRequest)

    @PostMapping("/mfa/verify")
    @ResponseStatus(HttpStatus.OK)
    fun verifyMfaLogin(
        @Valid @RequestBody request: MfaVerifyRequest,
        servletRequest: HttpServletRequest,
    ): MfaVerifyResponse =
        mfaAuthenticationService.verifyChallenge(request, servletRequest)

    @GetMapping("/me/passkeys")
    @ResponseStatus(HttpStatus.OK)
    fun listPasskeys(authentication: Authentication): List<PasskeyResponse> =
        passkeyService.listPasskeys(authentication.name)

    @DeleteMapping("/me/passkeys/{credentialId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deletePasskey(
        authentication: Authentication,
        @PathVariable credentialId: String,
    ) {
        passkeyService.deletePasskey(authentication.name, credentialId)
    }
}
