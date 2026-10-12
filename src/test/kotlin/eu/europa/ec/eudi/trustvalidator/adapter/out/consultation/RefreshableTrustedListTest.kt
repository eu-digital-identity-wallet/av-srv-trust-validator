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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

class RefreshableTrustedListTest {

    private class MutableClock(var instant: Instant) : Clock {
        override fun now(): Instant = instant
        operator fun plusAssign(duration: Duration) {
            instant += duration
        }
    }

    private val start = Instant.parse("2026-10-12T00:00:00Z")
    private val clock = MutableClock(start)

    private fun trustedList(sequenceNumber: Int, nextUpdate: Instant?) =
        TrustedList(URL, sequenceNumber, start, nextUpdate, emptyList())

    private fun refreshable(load: () -> TrustedList) =
        RefreshableTrustedList(URL, load, clock, maxRefreshInterval = 6.hours, retryInterval = 5.minutes)

    @Test
    fun `refresh is scheduled at the next update when it is due before the max refresh interval`() {
        val tl = trustedList(1, start + 1.hours)
        val refreshable = refreshable { tl }.apply { refresh() }

        assertSame(tl, refreshable.active())
        assertEquals(start + 1.hours, refreshable.nextRefresh())
    }

    @Test
    fun `refresh is scheduled at the max refresh interval when the next update is far away`() {
        val refreshable = refreshable { trustedList(1, start + 180.days) }.apply { refresh() }

        assertEquals(start + 6.hours, refreshable.nextRefresh())
    }

    @Test
    fun `a failed refresh keeps a still valid Trusted List and is retried`() {
        val tl = trustedList(1, start + 180.days)
        var fail = false
        val refreshable = refreshable { if (fail) throw TrustedListException("boom") else tl }.apply { refresh() }

        fail = true
        clock += 6.hours
        refreshable.refresh()

        assertSame(tl, refreshable.active())
        assertEquals(clock.now() + 5.minutes, refreshable.nextRefresh())
    }

    @Test
    fun `a newer Trusted List replaces the previous one`() {
        var sequenceNumber = 1
        val refreshable = refreshable { trustedList(sequenceNumber, start + 180.days) }.apply { refresh() }

        sequenceNumber = 2
        refreshable.refresh()

        assertEquals(2, refreshable.active()?.sequenceNumber)
    }

    @Test
    fun `a Trusted List is no longer used once its next update has passed`() {
        val tl = trustedList(1, start + 1.hours)
        var fail = false
        val refreshable = refreshable { if (fail) throw TrustedListException("boom") else tl }.apply { refresh() }

        fail = true
        clock += 1.hours
        refreshable.refresh()

        assertNull(refreshable.active())
    }

    @Test
    fun `no Trusted List is available when the initial load fails`() {
        val refreshable = refreshable { throw TrustedListException("boom") }.apply { refresh() }

        assertNull(refreshable.active())
        assertEquals(start + 5.minutes, refreshable.nextRefresh())
    }

    private companion object {
        const val URL = "https://example.com/tl.xml"
    }
}
