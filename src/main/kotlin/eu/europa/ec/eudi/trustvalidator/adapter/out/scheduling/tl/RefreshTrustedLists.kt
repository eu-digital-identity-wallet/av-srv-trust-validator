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
package eu.europa.ec.eudi.trustvalidator.adapter.out.scheduling.tl

import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.RefreshableTrustedList
import org.springframework.scheduling.Trigger
import org.springframework.scheduling.annotation.SchedulingConfigurer
import org.springframework.scheduling.config.ScheduledTaskRegistrar
import kotlin.time.toJavaInstant

/**
 * Refreshes each Trusted List at the time it determines itself, i.e. according to its next update information.
 */
class RefreshTrustedLists(private val trustedLists: Collection<RefreshableTrustedList>) : SchedulingConfigurer {

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        trustedLists.forEach { trustedList ->
            taskRegistrar.addTriggerTask(trustedList::refresh, Trigger { trustedList.nextRefresh().toJavaInstant() })
        }
    }
}
