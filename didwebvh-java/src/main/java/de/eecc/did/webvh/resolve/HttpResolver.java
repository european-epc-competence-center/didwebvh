package de.eecc.did.webvh.resolve;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.api.ResolveOptions;
import de.eecc.did.webvh.api.ResolveResult;
import de.eecc.did.webvh.exception.DidNotFoundException;
import de.eecc.did.webvh.exception.DidWebVhException;
import de.eecc.did.webvh.log.LogParser;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.model.DidLogEntry;
import de.eecc.did.webvh.model.DidDocumentMetadata;
import de.eecc.did.webvh.model.ResolutionMetadata;
import de.eecc.did.webvh.witness.WitnessProofCollection;
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
 * Resolves a {@code did:webvh} DID (or full DID URL) by fetching the log over HTTPS.
 *
 * <p>This resolver is the network-facing entry point. It handles four kinds of inputs:
 * <ol>
 *   <li><b>Base DID</b> — e.g. {@code did:webvh:{SCID}:example.com} → returns the
 *       resolved DID document.</li>
 *   <li><b>DID with fragment</b> — e.g. {@code did:webvh:{SCID}:example.com#key-1}
 *       → returns the dereferenced fragment node (existing behaviour).</li>
 *   <li><b>DID with path</b> — e.g. {@code did:webvh:{SCID}:example.com/governance/file.json}
 *       → resolves the base DID, then fetches the path resource via the implicit
 *       {@code #files} service and returns it as {@code contentStream}.</li>
 *   <li><b>DID with {@code /whois} path</b> — e.g.
 *       {@code did:webvh:{SCID}:example.com/whois} → fetches {@code whois.vp}
 *       via the implicit {@code #whois} service and returns it as {@code contentStream}.</li>
 * </ol>
 *
 * <p>Fetch behaviour:
 * <ul>
 *   <li>GET {@code {logUrl}} → {@code did.jsonl}</li>
 *   <li>If witnesses are configured: GET {@code {witnessUrl}} → {@code did-witness.json}</li>
 *   <li>If a DID URL path is present: GET {@code {pathUrl}} → resource content</li>
 *   <li>All connections MUST use HTTPS (spec requirement)</li>
 * </ul>
 *
 * <p>The actual HTTP I/O is delegated to a {@link LogFetcher}. This makes the resolver
 * testable without real network calls:
 * <ul>
 *   <li><b>Production:</b> use the {@linkplain #HttpResolver() no-arg constructor} which
 *       creates a built-in fetcher backed by {@link HttpClient}.</li>
 *   <li><b>Tests:</b> use {@link #HttpResolver(LogFetcher)} to inject a lambda that returns
 *       canned responses for both log files and path resources. The lambda can distinguish
 *       URLs by their suffix (e.g. {@code .jsonl}, {@code .vp}, {@code .json}).</li>
 * </ul>
 *
 * <p>The {@link de.eecc.did.webvh.crypto.Verifier} for proof validation is taken from
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
     * // Return canned JSONL from a test fixture, or VP content for /whois
     * LogFetcher testFetcher = url -> {
     *     if (url.endsWith("did.jsonl")) return myFixtureJsonl;
     *     if (url.endsWith("whois.vp")) return myFixtureVp;
     *     throw new IOException("Unexpected URL: " + url);
     * };
     * DidResolver resolver = new HttpResolver(testFetcher);
     * }</pre>
     *
     * @param logFetcher the fetcher to use for retrieving log, witness, and path resources
     */
    public HttpResolver(LogFetcher logFetcher) {
        Objects.requireNonNull(logFetcher, "logFetcher");
        this.delegate = new LogBasedResolver();
        this.logFetcher = logFetcher;
    }

    /**
     * Resolves a DID or full DID URL.
     *
     * <p>This is the single entry point for all resolution needs:
     * <ul>
     *   <li>Base DID → DID document</li>
     *   <li>DID + fragment → dereferenced node</li>
     *   <li>DID + path → dereferenced resource (returned in {@code contentStream})</li>
     * </ul>
     *
     * @param didUrl  the DID or DID URL string (may include path or fragment)
     * @param options resolution options including optional verifier and version filters
     * @return the resolution/dereferencing result; never {@code null}
     */
    @Override
    public ResolveResult resolve(String didUrl, ResolveOptions options) {
        log.trace("Received resolve request for DID URL: {}", didUrl);

        // ------------------------------------------------------------------
        // 1. Parse the DID URL into its constituent parts.
        //    A DID URL can contain a path (e.g. /whois) and/or a fragment (#key-1).
        //    We always resolve the BASE DID first (without path or fragment),
        //    then apply dereferencing on top of the resolved document.
        // ------------------------------------------------------------------
        String path = DidUrlTransformer.extractPath(didUrl);
        String fragment = DidUrlTransformer.extractFragment(didUrl);
        String baseDid = DidUrlTransformer.stripPathAndFragment(didUrl);

        try {
            // ------------------------------------------------------------------
            // 2. Resolve the base DID (no path, no fragment).
            //    This fetches did.jsonl, validates the log, and returns the DIDDoc.
            //    LogBasedResolver also injects implicit #files and #whois services
            //    into the returned document so that path dereferencing can find them.
            // ------------------------------------------------------------------
            String logUrl = DidUrlTransformer.toLogUrl(baseDid);
            String body = logFetcher.fetch(logUrl);
            DidLog didLog = LogParser.parse(body);

            ResolveOptions enrichedOptions = enrichWithWitnessProofs(baseDid, didLog, options);
            ResolveResult baseResult = delegate.resolve(baseDid, didLog, enrichedOptions);

            if (!baseResult.isSuccess()) {
                // Preserve the original didUrl in error results so the caller sees
                // the full DID URL they asked for, not the stripped base DID.
                return new ResolveResult(didUrl, null, baseResult.documentMetadata(),
                        baseResult.resolutionMetadata());
            }

            DidDocument document = baseResult.document();

            // ------------------------------------------------------------------
            // 3. Path dereferencing takes precedence over fragment dereferencing.
            //    If a path is present (e.g. /whois or /path/to/file), we look up
            //    the corresponding service (#whois or #files) in the DID document,
            //    construct the target HTTPS URL, fetch it, and return the content.
            // ------------------------------------------------------------------
            if (path != null && !path.isEmpty()) {
                return resolvePath(document, baseDid, didUrl, path, options);
            }

            // ------------------------------------------------------------------
            // 4. Fragment dereferencing (existing behaviour).
            //    If no path but a fragment is present, find the matching node
            //    (verification method, service, etc.) inside the DID document.
            // ------------------------------------------------------------------
            if (fragment != null) {
                document = FragmentDereferencer.dereference(document, fragment);
            }

            log.trace("Finished resolve for DID: {} success=true", didUrl);
            return new ResolveResult(didUrl, document,
                    baseResult.documentMetadata(), baseResult.resolutionMetadata());

        } catch (IOException e) {
            log.trace("HTTP fetch failed for DID {}: {}", didUrl, e.getMessage());
            return new ResolveResult(didUrl, null, DidDocumentMetadata.EMPTY,
                    ResolutionMetadata.error("notFound", "Not Found", e.getMessage()));
        } catch (DidNotFoundException e) {
            log.trace("DID not found {}: {}", didUrl, e.getMessage());
            return new ResolveResult(didUrl, null, DidDocumentMetadata.EMPTY,
                    ResolutionMetadata.error("notFound", "Not Found", e.getMessage()));
        } catch (DidWebVhException e) {
            log.trace("Resolution error for DID {}: {}", didUrl, e.getMessage());
            return new ResolveResult(didUrl, null, DidDocumentMetadata.EMPTY,
                    ResolutionMetadata.error("invalidDid", "Invalid DID", e.getMessage()));
        }
    }

    /**
     * Resolves a DID URL path by looking up the service in the DID document,
     * constructing the target URL, and fetching the resource.
     *
     * <p>The DID document must already have implicit services injected
     * (performed by {@link LogBasedResolver} before returning).</p>
     *
     * @param document  the resolved DID document with implicit services
     * @param baseDid   the base DID (without path or fragment)
     * @param didUrl    the original full DID URL (preserved for the result)
     * @param path      the extracted path (e.g. {@code "/whois"})
     * @param options   resolution options (may contain a custom resource fetcher)
     * @return a {@link ResolveResult} carrying the content in {@code contentStream}
     */
    private ResolveResult resolvePath(DidDocument document, String baseDid,
                                      String didUrl, String path, ResolveOptions options) {
        try {
            // Ask the path resolver to map the DID URL path to a concrete HTTPS URL.
            String targetUrl = DidUrlPathResolver.resolvePath(document, baseDid, path);
            log.trace("Dereferencing path '{}' for {} to URL: {}", path, didUrl, targetUrl);

            // Validate that the endpoint uses a supported scheme.
            if (!targetUrl.startsWith("https://") && !targetUrl.startsWith("http://")) {
                return new ResolveResult(didUrl, null, DidDocumentMetadata.EMPTY,
                        ResolutionMetadata.error("invalidDid", "Invalid DID",
                                "Unsupported service endpoint scheme: " + targetUrl));
            }

            String content = logFetcher.fetch(targetUrl);
            log.trace("Fetched {} bytes for path '{}'", content.length(), path);

            ResolutionMetadata successMeta = ResolutionMetadata.success(didUrl);
            return new ResolveResult(didUrl, successMeta, content);

        } catch (IOException e) {
            log.trace("Path fetch failed for {} (path={}): {}", didUrl, path, e.getMessage());
            return new ResolveResult(didUrl, null, DidDocumentMetadata.EMPTY,
                    ResolutionMetadata.error("notFound", "Not Found", e.getMessage()));
        } catch (DidNotFoundException e) {
            log.trace("Path resolution not found for {} (path={}): {}", didUrl, path, e.getMessage());
            return new ResolveResult(didUrl, null, DidDocumentMetadata.EMPTY,
                    ResolutionMetadata.error("notFound", "Not Found", e.getMessage()));
        } catch (DidWebVhException e) {
            log.trace("Path resolution error for {} (path={}): {}", didUrl, path, e.getMessage());
            return new ResolveResult(didUrl, null, DidDocumentMetadata.EMPTY,
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
