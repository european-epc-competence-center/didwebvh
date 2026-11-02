package de.eecc.did.webvh.operation;

import de.eecc.did.webvh.DidDocument;
import de.eecc.did.webvh.api.CreateOptions;
import de.eecc.did.webvh.api.CreateResult;
import de.eecc.did.webvh.api.DeactivateOptions;
import de.eecc.did.webvh.api.DidWebVh;
import de.eecc.did.webvh.api.ResolveOptions;
import de.eecc.did.webvh.api.UpdateOptions;
import de.eecc.did.webvh.crypto.Multiformats;
import de.eecc.did.webvh.crypto.Signer;
import de.eecc.did.webvh.exception.LogValidationException;
import de.eecc.did.webvh.log.LogParser;
import de.eecc.did.webvh.log.LogSerializer;
import de.eecc.did.webvh.model.DidLog;
import de.eecc.did.webvh.support.Ed25519TestFixture;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests that the write operations never hand back a log a resolver would reject, because
 * a published log entry cannot be taken back.
 */
class InvalidEntryGuardTest {

    private static final String DOMAIN = "example.com";

    private final Ed25519TestFixture keyA = Ed25519TestFixture.generate();

    private static CreateOptions.Builder createOptions(Ed25519TestFixture listed, Signer signer) {
        return CreateOptions.builder()
                .domain(DOMAIN)
                .initialDocument(DidDocument.fromJson("{\"id\":\"did:webvh:{SCID}:" + DOMAIN + "\"}"))
                .updateKeys(List.of(listed.publicKeyMultibase()))
                .signer(signer);
    }

    private static UpdateOptions.Builder updateOptions(DidLog log, CreateResult created, Signer signer) {
        return UpdateOptions.builder()
                .log(log)
                .updatedDocument(DidDocument.fromJson("{\"id\":\"" + created.did() + "\"}"))
                .signer(signer);
    }

    private static String hashOf(Ed25519TestFixture key) {
        return Multiformats.sha256Multihash(key.publicKeyMultibase().getBytes(StandardCharsets.UTF_8));
    }

    private CreateResult createDid() {
        return DidWebVh.create(createOptions(keyA, keyA.signer()).build());
    }

    @Test
    void createRejectsSignerNotInUpdateKeys() {
        Signer other = Ed25519TestFixture.generate().signer();

        assertThatThrownBy(() -> DidWebVh.create(createOptions(keyA, other).build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("not in active updateKeys");
    }

    @Test
    void createRejectsSignatureThatDoesNotVerify() {
        Signer broken = Signer.create(keyA.signer().getVerificationMethodId(), data -> new byte[64]);

        assertThatThrownBy(() -> DidWebVh.create(createOptions(keyA, broken).build()))
                .isInstanceOf(LogValidationException.class);
    }

    @Test
    void updateRejectsSignatureThatDoesNotVerify() {
        CreateResult created = createDid();
        Signer broken = Signer.create(keyA.signer().getVerificationMethodId(), data -> new byte[64]);

        assertThatThrownBy(() -> DidWebVh.update(updateOptions(created.log(), created, broken).build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("proof verification failed");
    }

    @Test
    void updateRejectsVersionTimeBeforePreviousEntry() {
        CreateResult created = createDid();

        assertThatThrownBy(() -> DidWebVh.update(updateOptions(created.log(), created, keyA.signer())
                        .versionTime(Instant.parse("2020-01-01T00:00:00Z"))
                        .build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("strictly after");
    }

    @Test
    void updateRejectsVersionTimeInTheFuture() {
        CreateResult created = createDid();

        assertThatThrownBy(() -> DidWebVh.update(updateOptions(created.log(), created, keyA.signer())
                        .versionTime(Instant.now().plus(Duration.ofDays(1)))
                        .build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("in the future");
    }

    @Test
    void updateRejectsCommittedSignerThatIsNotTheRevealedKey() {
        Ed25519TestFixture keyB = Ed25519TestFixture.generate();
        Ed25519TestFixture keyC = Ed25519TestFixture.generate();
        CreateResult created = DidWebVh.create(createOptions(keyA, keyA.signer())
                .nextKeyHashes(List.of(hashOf(keyB), hashOf(keyC)))
                .build());

        assertThatThrownBy(() -> DidWebVh.update(updateOptions(created.log(), created, keyC.signer())
                        .updateKeys(List.of(keyB.publicKeyMultibase()))
                        .nextKeyHashes(List.of(hashOf(Ed25519TestFixture.generate())))
                        .build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("not in active updateKeys");
    }

    @Test
    void updateBurstFailsInsteadOfProducingUnresolvableLog() {
        CreateResult created = createDid();

        assertThatThrownBy(() -> {
            DidLog log = created.log();
            for (int i = 0; i < 30; i++) {
                log = DidWebVh.update(updateOptions(log, created, keyA.signer()).build()).log();
            }
        })
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("in the future");
    }

    @Test
    void validUpdateStillResolves() {
        CreateResult created = createDid();

        DidLog updated = DidWebVh.update(updateOptions(created.log(), created, keyA.signer()).build()).log();

        DidLog reparsed = LogParser.parse(LogSerializer.serialize(updated));
        assertThat(DidWebVh.resolveFromLog(created.did(), reparsed, ResolveOptions.builder().build()).isSuccess())
                .isTrue();
    }

    @Test
    void updateRejectsPartiallyParsedLog() {
        CreateResult created = createDid();
        DidLog partial = LogParser.parse(LogSerializer.serialize(created.log()) + "{corrupt\n");
        assertThat(partial.isParsingComplete()).isFalse();

        assertThatThrownBy(() -> DidWebVh.update(updateOptions(partial, created, keyA.signer()).build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("partially parsed");
    }

    @Test
    void deactivateRejectsPartiallyParsedLog() {
        CreateResult created = createDid();
        DidLog partial = LogParser.parse(LogSerializer.serialize(created.log()) + "{corrupt\n");

        assertThatThrownBy(() -> DidWebVh.deactivate(
                        DeactivateOptions.builder().log(partial).signer(keyA.signer()).build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("partially parsed");
    }

    /** Changes the state of one entry without re-signing it, so its hash no longer matches. */
    private static DidLog tamperWithEntry(DidLog log, int lineIndex) {
        String[] lines = LogSerializer.serialize(log).split("\n");
        lines[lineIndex] = lines[lineIndex].replace("\"state\":{", "\"state\":{\"tampered\":true,");
        return LogParser.parse(String.join("\n", lines));
    }

    @Test
    void updateRejectsLogWithTamperedEarlierEntry() {
        CreateResult created = createDid();
        DidLog log = DidWebVh.update(updateOptions(created.log(), created, keyA.signer()).build()).log();
        DidLog tampered = tamperWithEntry(log, 0);

        assertThatThrownBy(() -> DidWebVh.update(updateOptions(tampered, created, keyA.signer()).build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("Refusing to append")
                .hasMessageContaining("Log entry 1");
    }

    @Test
    void updateRejectsLogWithTamperedLatestEntry() {
        CreateResult created = createDid();
        DidLog log = DidWebVh.update(updateOptions(created.log(), created, keyA.signer()).build()).log();
        DidLog tampered = tamperWithEntry(log, 1);

        assertThatThrownBy(() -> DidWebVh.update(updateOptions(tampered, created, keyA.signer()).build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("Refusing to append")
                .hasMessageContaining("Log entry 2");
    }

    @Test
    void deactivateRejectsLogWithTamperedEntry() {
        DidLog tampered = tamperWithEntry(createDid().log(), 0);

        assertThatThrownBy(() -> DidWebVh.deactivate(
                        DeactivateOptions.builder().log(tampered).signer(keyA.signer()).build()))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("Refusing to append")
                .hasMessageContaining("Log entry 1");
    }
}
