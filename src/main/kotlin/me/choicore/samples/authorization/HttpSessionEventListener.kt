package me.choicore.samples.authorization

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.context.event.EventListener
import org.springframework.session.events.SessionCreatedEvent
import org.springframework.session.events.SessionDeletedEvent
import org.springframework.session.events.SessionDestroyedEvent
import org.springframework.session.events.SessionExpiredEvent
import org.springframework.stereotype.Component

@Component
class HttpSessionEventListener {
    @EventListener
    fun processSessionCreatedEvent(event: SessionCreatedEvent) {
        log.info("Received session created event: ${event.sessionId}")
    }

    @EventListener
    fun processSessionDeletedEvent(event: SessionDeletedEvent) {
        log.info("Received session deleted event: ${event.sessionId}")
    }

    @EventListener
    fun processSessionDestroyedEvent(event: SessionDestroyedEvent) {
        log.info("Received session destroyed event: ${event.sessionId}")
    }

    @EventListener
    fun processSessionExpiredEvent(event: SessionExpiredEvent) {
        log.info("Received session expired event: ${event.sessionId}")
    }

    companion object {
        private val log: Logger = LoggerFactory.getLogger(HttpSessionEventListener::class.java)
    }
}
