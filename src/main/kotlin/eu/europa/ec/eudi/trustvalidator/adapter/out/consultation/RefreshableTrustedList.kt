/*
 * Copyright (c) 2025-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.trustvalidator.adapter.out.consultation

import org.slf4j.LoggerFactory
import java.security.cert.TrustAnchor
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant

private val log = LoggerFactory.getLogger(RefreshableTrustedList::class.java)

/**
 * A Trusted List that has been downloaded, and whose signature and validity have been verified.
 */
data class TrustedList(
    val url: String,
    val sequenceNumber: Int?,
    val issueDate: Instant?,
    val nextUpdate: Instant?,
    val trustAnchors: List<TrustAnchor>,
) {
    fun isValidAt(instant: Instant): Boolean = null == nextUpdate || instant < nextUpdate

    override fun toString(): String = "$url (sequence number $sequenceNumber, issued $issueDate, next update $nextUpdate)"
}

/**
 * Indicates that a Trusted List could not be loaded, or must not be used.
 */
class TrustedListException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Keeps the latest valid version of a Trusted List.
 *
 * A failed refresh never discards a list that is still valid. A list is no longer used once its next update has passed.
 *
 * @param url the distribution point of the Trusted List
 * @param load downloads and verifies the Trusted List, throwing in case it cannot be used
 * @param maxRefreshInterval upper bound for the time between two refreshes, so that lists re-issued before their next update are picked up
 * @param retryInterval time to wait before retrying a failed refresh
 */
class RefreshableTrustedList(
    val url: String,
    private val load: () -> TrustedList,
    private val clock: Clock,
    private val maxRefreshInterval: Duration,
    private val retryInterval: Duration,
) {
    @Volatile
    private var current: TrustedList? = null

    @Volatile
    private var nextRefresh: Instant = clock.now()

    /**
     * The Trusted List to use for verifications, or null when no valid Trusted List is available.
     */
    fun active(): TrustedList? = current?.takeIf { it.isValidAt(clock.now()) }

    /**
     * When the next refresh should take place.
     */
    fun nextRefresh(): Instant = nextRefresh

    fun refresh() {
        val now = clock.now()
        try {
            val loaded = load()
            current = loaded
            nextRefresh = minOf(now + maxRefreshInterval, loaded.nextUpdate ?: Instant.DISTANT_FUTURE)
            log.info("Loaded Trusted List $loaded with ${loaded.trustAnchors.size} trust anchor(s), next refresh at $nextRefresh")
        } catch (error: Exception) {
            val stillValid = active()
            nextRefresh = minOf(now + retryInterval, stillValid?.nextUpdate ?: Instant.DISTANT_FUTURE)
            if (null != stillValid) {
                log.warn(
                    "Refresh of Trusted List $url failed, keeping still valid Trusted List $stillValid, retrying at $nextRefresh",
                    error,
                )
            } else {
                log.error("Refresh of Trusted List $url failed and no valid Trusted List is available, retrying at $nextRefresh", error)
            }
        }
    }
}
