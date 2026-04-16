package io.didwebvh.resolve;

import java.io.IOException;

/**
 * Fetches the raw content of a {@code did.jsonl} or {@code did-witness.json} file
 * from a given HTTPS URL.
 *
 * <p>This is the I/O boundary for DID resolution. The {@link HttpResolver} delegates
 * all network access to a {@code LogFetcher}, keeping the resolution logic in
 * {@link LogBasedResolver} free of I/O concerns.
 *
 * <h3>Production use</h3>
 *
 * <p>In production, callers use the default {@link HttpResolver#HttpResolver() no-arg constructor},
 * which creates a built-in fetcher backed by {@link java.net.http.HttpClient}:
 * <pre>{@code
 * DidResolver resolver = new HttpResolver();
 * ResolveResult result = resolver.resolve("did:webvh:Qm...:example.com", options);
 * }</pre>
 *
 * <h3>Testing</h3>
 *
 * <p>In tests, inject a custom fetcher to avoid real HTTP calls. Because {@code LogFetcher}
 * is a {@code @FunctionalInterface}, a lambda is sufficient:
 * <pre>{@code
 * // Return canned JSONL from a test fixture
 * LogFetcher testFetcher = url -> myFixtureJsonl;
 *
 * DidResolver resolver = new HttpResolver(testFetcher);
 * ResolveResult result = resolver.resolve("did:webvh:Qm...:example.com", options);
 * }</pre>
 *
 * <p>For pure logic tests that don't involve HTTP at all, use
 * {@link LogBasedResolver#resolveFromLog} directly with an in-memory {@code DidLog}.
 *
 * @see HttpResolver
 * @see LogBasedResolver
 */
@FunctionalInterface
public interface LogFetcher {

    /**
     * Fetches the content at the given URL and returns it as a string.
     *
     * <p>The URL is produced by {@link DidUrlTransformer} and points to either
     * {@code did.jsonl} (JSON Lines) or {@code did-witness.json}.
     *
     * @param url the HTTPS URL to fetch
     * @return the response body as a string (never {@code null})
     * @throws IOException if the fetch fails (network error, non-2xx status, timeout, etc.)
     */
    String fetch(String url) throws IOException;
}
