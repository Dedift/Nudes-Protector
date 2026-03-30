package mm.nudesprotector.controller

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.bind.support.WebExchangeBindException

@RestControllerAdvice
class ApiExceptionHandler {
    @ExceptionHandler(WebExchangeBindException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleValidationException(exception: WebExchangeBindException): Map<String, Any> =
        mapOf(
            "message" to "Validation failed",
            "errors" to exception.bindingResult.fieldErrors.associate { fieldError ->
                fieldError.field to (fieldError.defaultMessage ?: "Invalid value")
            },
        )

    @ExceptionHandler(IllegalArgumentException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleIllegalArgumentException(exception: IllegalArgumentException): Map<String, String> =
        mapOf("message" to (exception.message ?: "Request cannot be processed"))

    @ExceptionHandler(IllegalStateException::class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    fun handleIllegalStateException(exception: IllegalStateException): Map<String, String> =
        mapOf("message" to (exception.message ?: "Internal server error"))
}
