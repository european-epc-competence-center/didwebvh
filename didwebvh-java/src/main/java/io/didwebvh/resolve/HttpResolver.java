package io.didwebvh.resolve;

import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;

import java.net.http.HttpClient;
import java.time.Duration;

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
 * <p>The {@link io.didwebvh.crypto.Verifier} for proof validation is taken from
 * {@link ResolveOptions#getVerifier()}.
 *
 * <p>Note: the spec recommends DNS-over-HTTPS (RFC 8484) during resolution to prevent
 * tracking. That is an option for future implementation.
 */
public final class HttpResolver implements DidResolver {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private final LogBasedResolver delegate;
    private final HttpClient httpClient;

    public HttpResolver() {
        this.delegate = new LogBasedResolver();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(DEFAULT_TIMEOUT)
                .build();
    }

    @Override
    public ResolveResult resolve(String did, ResolveOptions options) {
        // TODO: implement
        // 1. DidUrlTransformer.toLogUrl(did) → fetch did.jsonl
        // 2. If witnesses needed: DidUrlTransformer.toWitnessUrl(did) → fetch did-witness.json
        // 3. LogParser.parse(body) → DidLog
        // 4. delegate.resolveFromLog(did, log, options)
        throw new UnsupportedOperationException("TODO");
    }
}
