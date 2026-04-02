package io.didwebvh.log;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.model.DidLog;
import io.didwebvh.model.DidLogEntry;
import io.didwebvh.model.Parameters;
import io.didwebvh.model.proof.DataIntegrityProof;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link LogSerializer} verifying JSONL wire format output.
 */
class LogSerializerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // -------------------------------------------------------------------------
    // serializeLine
    // -------------------------------------------------------------------------

    @Test
    void serializeLine_minimalEntry_compactJson() {
        DidLogEntry entry = new DidLogEntry("1-zQmHash", "2025-01-23T04:12:36Z", null, null, null);
        String json = LogSerializer.serializeLine(entry);

        assertThat(json)
                .doesNotContain("\n")
                .doesNotContain("  ");
        assertThat(json).contains("\"versionId\":\"1-zQmHash\"");
        assertThat(json).contains("\"versionTime\":\"2025-01-23T04:12:36Z\"");
    }

    @Test
    void serializeLine_nullFieldsOmitted() {
        var entry = new DidLogEntry("1-zQmHash", "2025-01-23T04:12:36Z", null, null, null);
        String json = LogSerializer.serializeLine(entry);

        assertThat(json).doesNotContain("parameters");
        assertThat(json).doesNotContain("state");
        assertThat(json).doesNotContain("proof");
    }

    @Test
    void serializeLine_fullEntry_allFieldsPresent() {
        Parameters params = new Parameters("did:webvh:1.0", "zScid123", List.of("zKey1"), null, null, null, null, null, null);
        ObjectNode state = MAPPER.createObjectNode();
        state.put("id", "did:webvh:zScid123:example.com");
        DataIntegrityProof proof = DataIntegrityProof.of("zKey1", "2025-01-23T04:12:36Z", "zSigValue");

        DidLogEntry entry = new DidLogEntry("1-zQmHash", "2025-01-23T04:12:36Z", params, state, List.of(proof));
        String json = LogSerializer.serializeLine(entry);

        assertThat(json).contains("\"parameters\":");
        assertThat(json).contains("\"method\":\"did:webvh:1.0\"");
        assertThat(json).contains("\"scid\":\"zScid123\"");
        assertThat(json).contains("\"state\":{\"id\":\"did:webvh:zScid123:example.com\"}");
        assertThat(json).contains("\"proof\":[{");
        assertThat(json).contains("\"proofValue\":\"zSigValue\"");
    }

    @Test
    void serializeLine_rejectsNull() {
        assertThatThrownBy(() -> LogSerializer.serializeLine(null))
                .isInstanceOf(NullPointerException.class);
    }

    // -------------------------------------------------------------------------
    // serialize (full log)
    // -------------------------------------------------------------------------

    @Test
    void serialize_emptyLog_emptyString() {
        String jsonl = LogSerializer.serialize(DidLog.empty());
        assertThat(jsonl).isEmpty();
    }

    @Test
    void serialize_singleEntry_oneLineWithTrailingNewline() {
        DidLogEntry entry = new DidLogEntry("1-zQmHash", "2025-01-23T04:12:36Z", null, null, null);
        DidLog log = new DidLog(List.of(entry));

        String jsonl = LogSerializer.serialize(log);
        assertThat(jsonl).endsWith("\n");

        String[] lines = jsonl.split("\n", -1);
        assertThat(lines).hasSize(2);
        assertThat(lines[0]).isNotEmpty();
        assertThat(lines[1]).isEmpty();
    }

    @Test
    void serialize_multipleEntries_onePerLine() {
        DidLogEntry entry1 = new DidLogEntry("1-zQmHash1", "2025-01-23T04:12:36Z", null, null, null);
        DidLogEntry entry2 = new DidLogEntry("2-zQmHash2", "2025-01-24T10:00:00Z", null, null, null);
        DidLog log = new DidLog(List.of(entry1, entry2));

        String jsonl = LogSerializer.serialize(log);
        String[] lines = jsonl.split("\n", -1);

        assertThat(lines).hasSize(3);
        assertThat(lines[0]).contains("1-zQmHash1");
        assertThat(lines[1]).contains("2-zQmHash2");
        assertThat(lines[2]).isEmpty();
    }

    @Test
    void serialize_rejectsNull() {
        assertThatThrownBy(() -> LogSerializer.serialize(null))
                .isInstanceOf(NullPointerException.class);
    }

    // -------------------------------------------------------------------------
    // Wire format: compact, one object per line, no pretty-printing
    // -------------------------------------------------------------------------

    @Test
    void serialize_outputIsCompactNoWhitespaceInObjects() {
        Parameters params = new Parameters("did:webvh:1.0", "zScid", List.of("zKey"), null, null, null, null, null, null);
        ObjectNode state = MAPPER.createObjectNode();
        state.put("id", "did:webvh:zScid:example.com");
        DidLogEntry entry = new DidLogEntry("1-zQmHash", "2025-01-23T04:12:36Z", params, state, null);

        String line = LogSerializer.serializeLine(entry);

        // No line breaks within a single entry
        assertThat(line).doesNotContain("\n");
        assertThat(line).doesNotContain("\r");
        // Starts and ends with braces (JSON object)
        assertThat(line).startsWith("{");
        assertThat(line).endsWith("}");
    }
}
