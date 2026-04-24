package io.didwebvh.resolve;

import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;
import io.didwebvh.exception.DidNotFoundException;
import io.didwebvh.exception.DidWebVhException;
import io.didwebvh.log.LogParser;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.ResolutionMetadata;
import io.didwebvh.witness.WitnessProofCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * Resolves a did:webvh DID by fetching the log over HTTPS.
 *
 * <p>Fetch behaviour:
 * <ul>
 *   <li>GET {@code {logUrl}} → {@code did.jsonl}</li>
 *   <li>If witnesses are configured: GET {@code {witnessUrl}} → {@code did-witness.json}</li>
 *   <li>All connections MUST use HTTPS (spec requirement)</li>
 * </ul>
 *
 * <p>The actual HTTP I/O is delegated to a {@link LogFetcher}. This makes the resolver
 * testable without real network calls:
 * <ul>
 *   <li><b>Production:</b> use the {@linkplain #HttpResolver() no-arg constructor} which
 *       creates a built-in fetcher backed by {@link HttpClient}.</li>
 *   <li><b>Tests:</b> use {@link #HttpResolver(LogFetcher)} to inject a lambda that returns
 *       canned JSONL content.</li>
 * </ul>
 *
 * <p>The {@link io.didwebvh.crypto.Verifier} for proof validation is taken from
 * {@link ResolveOptions#getVerifier()}.
 *
 * <p>Note: the spec recommends DNS-over-HTTPS (RFC 8484) during resolution to prevent
 * tracking. That is an option for future implementation.
 */
public final class HttpResolver implements DidResolver {

    private static final Logger log = LoggerFactory.getLogger(HttpResolver.class);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private final LogBasedResolver delegate;
    private final LogFetcher logFetcher;

    /**
     * Creates a resolver with the built-in {@link HttpClient}-based fetcher.
     *
     * <p>This is the constructor for production use.
     */
    public HttpResolver() {
        this(defaultHttpFetcher());
    }

    /**
     * Creates a resolver with a custom {@link LogFetcher}.
     *
     * <p>Use this constructor in tests to inject a fetcher that returns canned responses:
     * <pre>{@code
     * LogFetcher testFetcher = url -> "{\"versionId\":\"1-Qm...\", ...}\n";
     * DidResolver resolver = new HttpResolver(testFetcher);
     * }</pre>
     *
     * @param logFetcher the fetcher to use for retrieving log and witness files
     */
    public HttpResolver(LogFetcher logFetcher) {
        Objects.requireNonNull(logFetcher, "logFetcher");
        this.delegate = new LogBasedResolver();
        this.logFetcher = logFetcher;
    }

    @Override
    public ResolveResult resolve(String did, ResolveOptions options) {
        log.trace("Received resolve request for DID: {}", did);
        try {
            String logUrl = DidUrlTransformer.toLogUrl(did);
            String body = logFetcher.fetch(logUrl);
            DidLog didLog = LogParser.parse(body);

            ResolveOptions enrichedOptions = enrichWithWitnessProofs(did, didLog, options);

            ResolveResult result = delegate.resolve(did, didLog, enrichedOptions);
            log.trace("Finished resolve for DID: {} success={}", did, result.isSuccess());
            return result;
        } catch (IOException e) {
            log.trace("HTTP fetch failed for DID {}: {}", did, e.getMessage());
            return new ResolveResult(did, null,
                    ResolutionMetadata.error("notFound", "Not Found", e.getMessage()));
        } catch (DidNotFoundException e) {
            log.trace("DID not found {}: {}", did, e.getMessage());
            return new ResolveResult(did, null,
                    ResolutionMetadata.error("notFound", "Not Found", e.getMessage()));
        } catch (DidWebVhException e) {
            log.trace("Resolution error for DID {}: {}", did, e.getMessage());
            return new ResolveResult(did, null,
                    ResolutionMetadata.error("invalidDid", "Invalid DID", e.getMessage()));
        }
    }

    /**
     * If any log entry declares witnesses, fetches {@code did-witness.json} and attaches
     * the parsed proofs to a copy of the options. Returns the original options unchanged
     * if no witnesses are configured or the witness file cannot be fetched.
     */
    private ResolveOptions enrichWithWitnessProofs(String did, DidLog didLog, ResolveOptions options) {
        if (options.getWitnessProofs() != null) {
            return options;
        }

        boolean hasWitnesses = didLog.entries().stream()
                .map(DidLogEntry::parameters)
                .anyMatch(p -> p != null && p.witness() != null && !p.witness().isEmpty());

        if (!hasWitnesses) {
            return options;
        }

        try {
            String witnessUrl = DidUrlTransformer.toWitnessUrl(did);
            log.trace("Fetching witness proofs from: {}", witnessUrl);
            String witnessBody = logFetcher.fetch(witnessUrl);
            WitnessProofCollection witnessProofs = WitnessProofCollection.parse(witnessBody);
            log.trace("Loaded {} witness proof entries", witnessProofs.entries().size());
            return options.toBuilder().witnessProofs(witnessProofs).build();
        } catch (IOException e) {
            log.trace("Could not fetch witness file for DID {}: {}", did, e.getMessage());
            return options;
        }
    }

    /**
     * Creates the default production fetcher backed by {@link HttpClient}.
     */
    private static LogFetcher defaultHttpFetcher() {
        var httpClient = HttpClient.newBuilder()
                .connectTimeout(DEFAULT_TIMEOUT)
                .build();

        return url -> {
            log.trace("Fetching URL: {}", url);
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(DEFAULT_TIMEOUT)
                    .GET()
                    .build();
            try {
                var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() >= 400) {
                    throw new IOException("HTTP " + response.statusCode() + " for " + url);
                }
                log.trace("Fetched {} bytes from {}", response.body().length(), url);
                return response.body();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while fetching " + url, e);
            }
        };
    }
}
