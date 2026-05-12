package de.eecc.did.webvh.witness;

import de.eecc.did.webvh.model.WitnessParameter;

/**
 * A contiguous run of log entries governed by a single witness configuration.
 *
 * <p>Spec semantics:
 * <ul>
 *   <li>{@code firstVersion} is the first log entry number (1-indexed) where this config
 *       became active.</li>
 *   <li>{@code lastVersion} is the last log entry number where this config was still active.</li>
 *   <li>An epoch with {@code firstVersion <= V} applies to a historical query at version {@code V},
 *       even if {@code lastVersion > V}.</li>
 * </ul>
 *
 * @param config      the witness configuration active during this epoch
 * @param firstVersion the first log entry number (1-indexed) where this config became active
 * @param lastVersion  the last log entry number where this config was still active
 */
public record WitnessEpoch(
        WitnessParameter config,
        int firstVersion,
        int lastVersion
) {
}
