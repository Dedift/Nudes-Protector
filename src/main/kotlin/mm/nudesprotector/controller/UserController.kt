package mm.nudesprotector.controller

import jakarta.validation.Valid
import mm.nudesprotector.domain.dto.request.CreateUserRequest
import mm.nudesprotector.domain.dto.request.VerifyEmailRequest
import mm.nudesprotector.domain.dto.response.CreateUserResponse
import mm.nudesprotector.domain.dto.response.VerifyEmailResponse
import mm.nudesprotector.mail.EmailVerificationService
import mm.nudesprotector.service.UserRegistrationService
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
@RequestMapping("/users")
class UserController(
    private val userRegistrationService: UserRegistrationService,
    private val emailVerificationService: EmailVerificationService,
) {
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    fun createUser(@Valid @RequestBody request: CreateUserRequest): Mono<CreateUserResponse> =
        userRegistrationService.createUser(request)

    @PostMapping("/verify-email")
    @ResponseStatus(HttpStatus.OK)
    fun verifyEmail(@Valid @RequestBody request: VerifyEmailRequest): Mono<VerifyEmailResponse> =
        emailVerificationService.verifyEmail(request)
}
