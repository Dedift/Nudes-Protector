package mm.nudesprotector.service

import org.springframework.beans.factory.annotation.Value
import org.springframework.mail.SimpleMailMessage
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers

@Service
class EmailVerificationMailService(
    private val mailSender: JavaMailSender,
    @Value($$"${app.mail.from:noreply@nudesprotector.local}")
    private val fromAddress: String,
) {
    fun sendVerificationCode(email: String, code: String): Mono<Void> =
        Mono.fromCallable {
            val message = SimpleMailMessage()
            message.from = fromAddress
            message.setTo(email)
            message.subject = "Email verification code"
            message.text = "Your email verification code is: $code"
            mailSender.send(message)
        }
            .subscribeOn(Schedulers.boundedElastic())
            .then()
}
