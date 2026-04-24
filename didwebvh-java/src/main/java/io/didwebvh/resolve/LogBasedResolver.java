package io.didwebvh.resolve;

import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;
import io.didwebvh.exception.DidNotFoundException;
import io.didwebvh.exception.DidWebVhException;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.log.LogValidator;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.ResolutionMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Resolves a DID from an in-memory {@link DidLog} without any network access.
 *
 * <p>This is the core resolution engine. It validates the log chain entry-by-entry,
 * applies version filters, handles deactivation, and builds resolution metadata.
 *
 * <p>This class does not implement {@link DidResolver} because its method signature
 * requires a {@link DidLog} parameter. Use {@link HttpResolver} for the network-facing
 * {@link DidResolver} contract.
 *
 * <p>Resolution never throws exceptions to the caller. All errors are encoded in
 * {@link ResolveResult#metadata()} per the DID Resolution spec.
 *
 * @see HttpResolver
 */
public final class LogBasedResolver {

    private static final Logger log = LoggerFactory.getLogger(LogBasedResolver.class);

    private static final String ERROR_INVALID_DID = "invalidDid";
    private static final String ERROR_NOT_FOUND = "notFound";

    public LogBasedResolver() {}

    /**
     * Resolves the DID from the given pre-fetched log.
     *
     * @param did     the DID string (used for the result; not re-parsed here)
     * @param didLog  the pre-parsed log (must be non-empty)
     * @param options resolution options including the verifier and optional version filters
     * @return the resolution result; never {@code null}; errors are in
     *         {@link ResolveResult#metadata()}, never thrown
     */
    public ResolveResult resolve(String did, DidLog didLog, ResolveOptions options) {
        log.trace("Received resolve request for DID: {}", did);
        validateInputs(did, didLog, options);
        try {
            return doResolve(did, didLog, options);
        } catch (DidNotFoundException e) {
            log.trace("Resolution failed (notFound) for {}: {}", did, e.getMessage());
            return errorResult(did, ERROR_NOT_FOUND, "Not Found", e.getMessage());
        } catch (DidWebVhException e) {
            log.trace("Resolution failed (invalidDid) for {}: {}", did, e.getMessage());
            return errorResult(did, ERROR_INVALID_DID, "Invalid DID", e.getMessage());
        } catch (Exception e) {
            log.trace("Resolution failed (unexpected) for {}: {}", did, e.getMessage());
            return errorResult(did, ERROR_INVALID_DID, "Resolution Error", e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Core resolution logic
    // -------------------------------------------------------------------------

    private ResolveResult doResolve(String did, DidLog didLog, ResolveOptions options) {
        List<ValidatedEntry> validEntries = validateLog(didLog, options);
        if (validEntries.isEmpty()) {
            return errorResult(did, ERROR_INVALID_DID, "Invalid DID",
                    "No valid entries in the DID log");
        }

        boolean logFullyValid = validEntries.size() == didLog.size() && didLog.isParsingComplete();

        // Spec §resolve step 6.1: the SCID in the DID being resolved
        // MUST match the SCID declared in the genesis log entry.
        ValidatedEntry genesis = validEntries.get(0);
        String scidFromDid = DidUrlTransformer.extractScid(did);
        String scidFromLog = genesis.entry().parameters().scid();
        if (!scidFromDid.equals(scidFromLog)) {
            throw new LogValidationException(
                    "SCID in DID '" + scidFromDid + "' does not match SCID in log '" + scidFromLog + "'");
        }

        validateFilters(options);

        boolean isLatestQuery = noVersionFilter(options);

        if (!logFullyValid && isLatestQuery) {
            log.trace("Log not fully valid for DID {} — cannot resolve latest", did);
            throw new LogValidationException(
                    "Log validation failed: only " + validEntries.size() + " of "
                            + didLog.size() + " entries are valid (parsingComplete="
                            + didLog.isParsingComplete() + ")");
        }

        ValidatedEntry target = selectVersion(validEntries, options, didLog);
        ValidatedEntry latest = validEntries.get(validEntries.size() - 1);

        boolean currentlyDeactivated = latest.effectiveParams().isDeactivated();

        if (currentlyDeactivated && isLatestQuery) {
            log.trace("DID {} is deactivated, returning null document", did);
            return deactivatedResult(did, latest, genesis);
        }

        ResolutionMetadata metadata = buildMetadata(target, latest, genesis, currentlyDeactivated);
        log.trace("Successfully resolved DID {} at version {}", did, target.entry().versionId());
        return new ResolveResult(did, target.entry().state(), metadata);
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    private static void validateInputs(String did, DidLog didLog, ResolveOptions options) {
        Objects.requireNonNull(did, "did must not be null");
        Objects.requireNonNull(didLog, "didLog must not be null");
        Objects.requireNonNull(options, "options must not be null");
        Objects.requireNonNull(options.getVerifier(), "options.verifier must not be null");
    }

    private static void validateFilters(ResolveOptions options) {
        int filterCount = 0;
        if (options.getVersionId() != null) filterCount++;
        if (options.getVersionTime() != null) filterCount++;
        if (options.getVersionNumber() != null) filterCount++;
        if (filterCount > 1) {
            throw new DidNotFoundException(
                    "Conflicting version filters: at most one of versionId, versionTime, versionNumber may be specified");
        }
    }

    /**
     * Walks the log entry-by-entry, delegating per-entry validation to
     * {@link LogValidator#validateEntry}. Stops at the first invalid entry.
     */
    private static List<ValidatedEntry> validateLog(DidLog didLog, ResolveOptions options) {
        if (didLog.isEmpty()) {
            return List.of();
        }

        LogValidator validator = new LogValidator(options.getVerifier());
        List<ValidatedEntry> result = new ArrayList<>();
        Parameters activeParams = null;
        DidLogEntry previous = null;

        for (int i = 0; i < didLog.size(); i++) {
            DidLogEntry entry = didLog.entries().get(i);
            try {
                activeParams = validator.validateEntry(entry, previous, activeParams);
                result.add(new ValidatedEntry(entry, activeParams));
                previous = entry;
            } catch (DidWebVhException e) {
                log.trace("Log validation stopped at entry {}: {}", i + 1, e.getMessage());
                break;
            }
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // Version selection
    // -------------------------------------------------------------------------

    private static ValidatedEntry selectVersion(List<ValidatedEntry> validEntries, ResolveOptions options,
                                                DidLog fullLog) {
        if (options.getVersionId() != null) {
            return findByVersionId(validEntries, options.getVersionId(), fullLog);
        }
        if (options.getVersionTime() != null) {
            return findByVersionTime(validEntries, options.getVersionTime());
        }
        if (options.getVersionNumber() != null) {
            return findByVersionNumber(validEntries, options.getVersionNumber(), fullLog);
        }
        return validEntries.get(validEntries.size() - 1);
    }

    private static ValidatedEntry findByVersionId(List<ValidatedEntry> entries, String versionId,
                                                  DidLog fullLog) {
        var match = entries.stream()
                .filter(v -> versionId.equals(v.entry().versionId()))
                .findFirst();
        if (match.isPresent()) {
            return match.get();
        }
        boolean existsInFullLog = fullLog.entries().stream()
                .anyMatch(e -> versionId.equals(e.versionId()));
        if (existsInFullLog) {
            throw new LogValidationException(
                    "Entry with versionId '" + versionId + "' exists but failed validation");
        }
        throw new DidNotFoundException("No entry matches versionId '" + versionId + "'");
    }

    private static ValidatedEntry findByVersionTime(List<ValidatedEntry> entries, Instant versionTime) {
        ValidatedEntry match = null;
        for (ValidatedEntry v : entries) {
            Instant entryTime = Instant.parse(v.entry().versionTime());
            if (!entryTime.isAfter(versionTime)) {
                match = v;
            } else {
                break;
            }
        }
        if (match == null) {
            throw new DidNotFoundException(
                    "No entry active at versionTime '" + versionTime + "'");
        }
        return match;
    }

    private static ValidatedEntry findByVersionNumber(List<ValidatedEntry> entries, int versionNumber,
                                                      DidLog fullLog) {
        var match = entries.stream()
                .filter(v -> v.entry().versionNumber() == versionNumber)
                .findFirst();
        if (match.isPresent()) {
            return match.get();
        }
        boolean existsInFullLog = fullLog.entries().stream()
                .anyMatch(e -> e.versionNumber() == versionNumber);
        if (existsInFullLog) {
            throw new LogValidationException(
                    "Entry with versionNumber " + versionNumber + " exists but failed validation");
        }
        if (!fullLog.isParsingComplete() && !entries.isEmpty()
                && versionNumber > entries.get(entries.size() - 1).entry().versionNumber()) {
            throw new LogValidationException(
                    "Entry with versionNumber " + versionNumber
                            + " could not be parsed (log parsing incomplete)");
        }
        throw new DidNotFoundException("No entry matches versionNumber " + versionNumber);
    }

    // -------------------------------------------------------------------------
    // Metadata building
    // -------------------------------------------------------------------------

    private static ResolutionMetadata buildMetadata(ValidatedEntry target, ValidatedEntry latest,
                                                    ValidatedEntry genesis, boolean currentlyDeactivated) {
        Parameters params = target.effectiveParams();
        String scid = genesis.entry().parameters().scid();

        return ResolutionMetadata.builder()
                .versionId(target.entry().versionId())
                .versionNumber(target.entry().versionNumber())
                .versionTime(target.entry().versionTime())
                .created(genesis.entry().versionTime())
                .updated(latest.entry().versionTime())
                .scid(scid)
                .portable(Boolean.TRUE.equals(params.portable()))
                .deactivated(currentlyDeactivated)
                .ttl(params.ttl() != null ? String.valueOf(params.ttl()) : null)
                .witness(params.witness())
                .watchers(params.watchers())
                .build();
    }

    private static ResolveResult deactivatedResult(String did, ValidatedEntry latest,
                                                   ValidatedEntry genesis) {
        String scid = genesis.entry().parameters().scid();
        Parameters params = latest.effectiveParams();

        ResolutionMetadata metadata = ResolutionMetadata.builder()
                .versionId(latest.entry().versionId())
                .versionNumber(latest.entry().versionNumber())
                .versionTime(latest.entry().versionTime())
                .created(genesis.entry().versionTime())
                .updated(latest.entry().versionTime())
                .scid(scid)
                .portable(Boolean.TRUE.equals(params.portable()))
                .deactivated(true)
                .ttl(params.ttl() != null ? String.valueOf(params.ttl()) : null)
                .witness(params.witness())
                .watchers(params.watchers())
                .build();

        return new ResolveResult(did, null, metadata);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static boolean noVersionFilter(ResolveOptions options) {
        return options.getVersionId() == null
                && options.getVersionTime() == null
                && options.getVersionNumber() == null;
    }

    private static ResolveResult errorResult(String did, String errorCode, String title, String detail) {
        return new ResolveResult(did, null, ResolutionMetadata.error(errorCode, title, detail));
    }

    /**
     * A validated log entry paired with the effective parameter state after that entry.
     */
    record ValidatedEntry(DidLogEntry entry, Parameters effectiveParams) {}
}
