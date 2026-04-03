package io.didwebvh.log;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.exception.LogValidationException;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link LogParser} verifying JSONL deserialization.
 */
class LogParserTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // -------------------------------------------------------------------------
    // parseLine — single entry
    // -------------------------------------------------------------------------

    @Test
    void parseLine_minimalEntry() {
        String json = "{\"versionId\":\"1-QmHash\",\"versionTime\":\"2025-01-23T04:12:36Z\"}";
        DidLogEntry entry = LogParser.parseLine(json);

        assertThat(entry.versionId()).isEqualTo("1-QmHash");
        assertThat(entry.versionTime()).isEqualTo("2025-01-23T04:12:36Z");
        assertThat(entry.parameters()).isNull();
        assertThat(entry.state()).isNull();
        assertThat(entry.proof()).isNull();
    }

    @Test
    void parseLine_fullEntry() {
        String json = """
                {"versionId":"1-QmHash","versionTime":"2025-01-23T04:12:36Z",\
                "parameters":{"method":"did:webvh:1.0","scid":"Scid123","updateKeys":["Key1"]},\
                "state":{"id":"did:webvh:Scid123:example.com"},\
                "proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022",\
                "verificationMethod":"Key1","created":"2025-01-23T04:12:36Z",\
                "proofPurpose":"assertionMethod","proofValue":"SigValue"}]}""";

        DidLogEntry entry = LogParser.parseLine(json);

        assertThat(entry.parameters().method()).isEqualTo("did:webvh:1.0");
        assertThat(entry.parameters().scid()).isEqualTo("Scid123");
        assertThat(entry.parameters().updateKeys()).containsExactly("Key1");
        assertThat(entry.state().get("id").asText()).isEqualTo("did:webvh:Scid123:example.com");
        assertThat(entry.proof()).hasSize(1);
        assertThat(entry.proof().get(0).proofValue()).isEqualTo("SigValue");
    }

    @Test
    void parseLine_unknownFieldsIgnored() {
        String json = "{\"versionId\":\"1-QmHash\",\"versionTime\":\"2025-01-23T04:12:36Z\",\"unknownField\":42}";
        DidLogEntry entry = LogParser.parseLine(json);

        assertThat(entry.versionId()).isEqualTo("1-QmHash");
    }

    @Test
    void parseLine_invalidJson_throws() {
        assertThatThrownBy(() -> LogParser.parseLine("not valid json"))
                .isInstanceOf(LogValidationException.class);
    }

    @Test
    void parseLine_rejectsNull() {
        assertThatThrownBy(() -> LogParser.parseLine(null))
                .isInstanceOf(NullPointerException.class);
    }

    // -------------------------------------------------------------------------
    // parse — full JSONL
    // -------------------------------------------------------------------------

    @Test
    void parse_singleEntry() {
        String jsonl = "{\"versionId\":\"1-QmHash\",\"versionTime\":\"2025-01-23T04:12:36Z\"}\n";
        DidLog log = LogParser.parse(jsonl);

        assertThat(log.size()).isEqualTo(1);
        assertThat(log.first().versionId()).isEqualTo("1-QmHash");
    }

    @Test
    void parse_multipleEntries() {
        String jsonl = "{\"versionId\":\"1-QmHash1\",\"versionTime\":\"2025-01-23T04:12:36Z\"}\n"
                + "{\"versionId\":\"2-QmHash2\",\"versionTime\":\"2025-01-24T10:00:00Z\"}\n";
        DidLog log = LogParser.parse(jsonl);

        assertThat(log.size()).isEqualTo(2);
        assertThat(log.first().versionId()).isEqualTo("1-QmHash1");
        assertThat(log.latest().versionId()).isEqualTo("2-QmHash2");
    }

    @Test
    void parse_toleratesTrailingNewline() {
        String jsonl = "{\"versionId\":\"1-QmHash\",\"versionTime\":\"2025-01-23T04:12:36Z\"}\n\n";
        DidLog log = LogParser.parse(jsonl);

        assertThat(log.size()).isEqualTo(1);
    }

    @Test
    void parse_toleratesBlankLines() {
        String jsonl = "\n{\"versionId\":\"1-QmHash\",\"versionTime\":\"2025-01-23T04:12:36Z\"}\n\n"
                + "{\"versionId\":\"2-QmHash2\",\"versionTime\":\"2025-01-24T10:00:00Z\"}\n\n";
        DidLog log = LogParser.parse(jsonl);

        assertThat(log.size()).isEqualTo(2);
    }

    @Test
    void parse_emptyString_emptyLog() {
        assertThat(LogParser.parse("").isEmpty()).isTrue();
    }

    @Test
    void parse_onlyNewlines_emptyLog() {
        assertThat(LogParser.parse("\n\n\n").isEmpty()).isTrue();
    }

    @Test
    void parse_invalidLine_throwsWithLineNumber() {
        String jsonl = "{\"versionId\":\"1-QmHash\",\"versionTime\":\"2025-01-23T04:12:36Z\"}\n"
                + "broken json\n";

        assertThatThrownBy(() -> LogParser.parse(jsonl))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("line 2");
    }

    @Test
    void parse_rejectsNull() {
        assertThatThrownBy(() -> LogParser.parse(null))
                .isInstanceOf(NullPointerException.class);
    }

    // -------------------------------------------------------------------------
    // Round-trip: serialize → parse
    // -------------------------------------------------------------------------

    @Test
    void roundTrip_serializeThenParse_preservesData() {
        Parameters params = new Parameters("did:webvh:1.0", "Scid123", List.of("Key1"), null, null, null, null, null, null);
        ObjectNode state = MAPPER.createObjectNode();
        state.put("id", "did:webvh:Scid123:example.com");
        state.putArray("verificationMethod").addObject()
                .put("id", "did:webvh:Scid123:example.com#key-1")
                .put("type", "Multikey")
                .put("controller", "did:webvh:Scid123:example.com")
                .put("publicKeyMultibase", "Key1");
        DataIntegrityProof proof = DataIntegrityProof.of("Key1", "2025-01-23T04:12:36Z", "SigValue");

        DidLogEntry entry1 = new DidLogEntry("1-QmHash1", "2025-01-23T04:12:36Z", params, state, List.of(proof));
        DidLogEntry entry2 = new DidLogEntry("2-QmHash2", "2025-01-24T10:00:00Z",
                new Parameters(null, null, null, null, null, null, null, null, null), state, List.of(proof));

        DidLog originalLog = new DidLog(List.of(entry1, entry2));
        String jsonl = LogSerializer.serialize(originalLog);
        DidLog parsedLog = LogParser.parse(jsonl);

        assertThat(parsedLog.size()).isEqualTo(originalLog.size());

        DidLogEntry parsed1 = parsedLog.first();
        assertThat(parsed1.versionId()).isEqualTo("1-QmHash1");
        assertThat(parsed1.versionTime()).isEqualTo("2025-01-23T04:12:36Z");
        assertThat(parsed1.parameters().method()).isEqualTo("did:webvh:1.0");
        assertThat(parsed1.parameters().scid()).isEqualTo("Scid123");
        assertThat(parsed1.parameters().updateKeys()).containsExactly("Key1");
        assertThat(parsed1.state().get("id").asText()).isEqualTo("did:webvh:Scid123:example.com");
        assertThat(parsed1.proof()).hasSize(1);
        assertThat(parsed1.proof().get(0).proofValue()).isEqualTo("SigValue");
        assertThat(parsed1.proof().get(0).cryptosuite()).isEqualTo("eddsa-jcs-2022");

        DidLogEntry parsed2 = parsedLog.latest();
        assertThat(parsed2.versionId()).isEqualTo("2-QmHash2");
        assertThat(parsed2.versionNumber()).isEqualTo(2);
    }

    @Test
    void roundTrip_parseThenSerialize_stableOutput() {
        String originalJsonl = "{\"versionId\":\"1-QmHash\",\"versionTime\":\"2025-01-23T04:12:36Z\","
                + "\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Scid\",\"updateKeys\":[\"Key1\"]}}\n";

        DidLog log = LogParser.parse(originalJsonl);
        String reserializedJsonl = LogSerializer.serialize(log);
        DidLog reparsedLog = LogParser.parse(reserializedJsonl);

        assertThat(reparsedLog.size()).isEqualTo(log.size());
        assertThat(reparsedLog.first().versionId()).isEqualTo(log.first().versionId());
        assertThat(reparsedLog.first().parameters().method()).isEqualTo(log.first().parameters().method());
    }

    // -------------------------------------------------------------------------
    // Parameters serialization edge cases
    // -------------------------------------------------------------------------

    @Test
    void roundTrip_parametersWithOptionalFields() {
        Parameters params = new Parameters("did:webvh:1.0", "Scid", List.of("Key1"),
                List.of("Hash1", "Hash2"), true, false, 7200, null, List.of("https://watcher.example.com"));
        DidLogEntry entry = new DidLogEntry("1-QmHash", "2025-01-23T04:12:36Z", params, null, null);

        String json = LogSerializer.serializeLine(entry);
        DidLogEntry parsed = LogParser.parseLine(json);

        assertThat(parsed.parameters().nextKeyHashes()).containsExactly("Hash1", "Hash2");
        assertThat(parsed.parameters().portable()).isTrue();
        assertThat(parsed.parameters().deactivated()).isFalse();
        assertThat(parsed.parameters().ttl()).isEqualTo(7200);
        assertThat(parsed.parameters().watchers()).containsExactly("https://watcher.example.com");
    }

    @Test
    void roundTrip_entryWithoutProof_proofIsNull() {
        DidLogEntry entry = new DidLogEntry("1-QmHash", "2025-01-23T04:12:36Z", null, null, null);

        String json = LogSerializer.serializeLine(entry);
        DidLogEntry parsed = LogParser.parseLine(json);

        assertThat(parsed.proof()).isNull();
    }
}
