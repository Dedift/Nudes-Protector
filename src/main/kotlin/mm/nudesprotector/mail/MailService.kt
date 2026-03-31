package mm.nudesprotector.mail

import org.springframework.beans.factory.annotation.Value
import org.springframework.mail.SimpleMailMessage
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers

@Service
class MailService(
    private val mailSender: JavaMailSender,
    @Value($$"${app.mail.from:noreply@nudesprotector.local}")
    private val fromAddress: String,
) {
    fun sendTextMail(
        email: String,
        subject: String,
        text: String,
    ): Mono<Void> =
        Mono.fromCallable {
            val message = SimpleMailMessage()
            message.from = fromAddress
            message.setTo(email)
            message.subject = subject
            message.text = text
            mailSender.send(message)
        }
            .subscribeOn(Schedulers.boundedElastic())
            .then()
}
