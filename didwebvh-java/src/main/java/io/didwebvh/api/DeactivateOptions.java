package io.didwebvh.api;

/**
 * Options for the {@link DidWebVh#deactivate} operation.
 *
 * <p>Currently no additional options are required beyond the log and signing key,
 * which are passed directly to the operation. Reserved for future extensibility.
 */
public final class DeactivateOptions {

    private DeactivateOptions() {}

    /** Returns a default (empty) options instance. */
    public static DeactivateOptions defaults() {
        return new DeactivateOptions();
    }
}
