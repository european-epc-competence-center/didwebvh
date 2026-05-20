package de.eecc.did.webvh;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.eecc.did.webvh.util.JsonMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An immutable, consumer-friendly wrapper around a JSON object.
 *
 * <p>Hides Jackson's {@link JsonNode} from the public API while preserving
 * the library's ability to use Jackson internally for parsing, canonicalisation,
 * and signing.</p>
 *
 * <p>Instances are immutable. All mutation is done via the nested
 * {@link Builder}.</p>
 */
@JsonSerialize(using = DidDocumentSerializer.class)
@JsonDeserialize(using = DidDocumentDeserializer.class)
public final class DidDocument {

    private static final ObjectMapper MAPPER = JsonMapper.INSTANCE;

    private final JsonNode node;

    /**
     * Constructs a wrapper around the given Jackson node.
     *
     * <p>Must remain {@code public} for Jackson deserialization. Consumers should prefer
     * {@link #fromJson}, {@link #fromMap}, or the {@link Builder}.</p>
     *
     * @param node the Jackson {@link JsonNode} to wrap
     */
    public DidDocument(JsonNode node) {
        this.node = Objects.requireNonNull(node);
    }

    /** Parses a JSON string into a {@code DidDocument}. */
    public static DidDocument fromJson(String json) {
        Objects.requireNonNull(json, "json must not be null");
        try {
            return new DidDocument(MAPPER.readTree(json));
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid JSON", e);
        }
    }

    /** Converts a {@code Map} into a {@code DidDocument}. */
    public static DidDocument fromMap(Map<String, Object> map) {
        Objects.requireNonNull(map, "map must not be null");
        return new DidDocument(MAPPER.valueToTree(map));
    }

    /** Package-private access to the underlying Jackson node (library-internal use only). */
    JsonNode asJsonNode() {
        return node;
    }

    // -------------------------------------------------------------------------
    // Typed accessors
    // -------------------------------------------------------------------------

    /**
     * Returns the string value of the given field, or {@code null} if missing.
     *
     * @param field the JSON field name
     * @return the string value, or {@code null} if the field is missing
     */
    public String getString(String field) {
        return getString(field, null);
    }

    /**
     * Returns the string value of the given field, or {@code defaultValue} if missing.
     *
     * @param field        the JSON field name
     * @param defaultValue the value to return if the field is missing
     * @return the string value, or {@code defaultValue} if the field is missing
     */
    public String getString(String field, String defaultValue) {
        JsonNode value = node.path(field);
        return value.isMissingNode() ? defaultValue : value.asText(defaultValue);
    }

    /**
     * Returns the boolean value of the given field, or {@code false} if missing.
     *
     * @param field the JSON field name
     * @return the boolean value, or {@code false} if the field is missing
     */
    public boolean getBoolean(String field) {
        return getBoolean(field, false);
    }

    /**
     * Returns the boolean value of the given field, or {@code defaultValue} if missing.
     *
     * @param field        the JSON field name
     * @param defaultValue the value to return if the field is missing
     * @return the boolean value, or {@code defaultValue} if the field is missing
     */
    public boolean getBoolean(String field, boolean defaultValue) {
        JsonNode value = node.path(field);
        return value.isMissingNode() ? defaultValue : value.asBoolean(defaultValue);
    }

    /**
     * Returns the int value of the given field, or {@code 0} if missing.
     *
     * @param field the JSON field name
     * @return the int value, or {@code 0} if the field is missing
     */
    public int getInt(String field) {
        return getInt(field, 0);
    }

    /**
     * Returns the int value of the given field, or {@code defaultValue} if missing.
     *
     * @param field        the JSON field name
     * @param defaultValue the value to return if the field is missing
     * @return the int value, or {@code defaultValue} if the field is missing
     */
    public int getInt(String field, int defaultValue) {
        JsonNode value = node.path(field);
        return value.isMissingNode() ? defaultValue : value.asInt(defaultValue);
    }

    /**
     * Returns the nested object at the given field as a {@code DidDocument},
     * or {@code null} if the field is missing or not an object.
     *
     * @param field the JSON field name
     * @return the nested object as a {@code DidDocument}, or {@code null}
     */
    public DidDocument getObject(String field) {
        JsonNode value = node.path(field);
        return value.isObject() ? new DidDocument(value) : null;
    }

    /**
     * Returns the array of strings at the given field, or an empty list if missing / not an array.
     *
     * @param field the JSON field name
     * @return the list of strings, or an empty list if the field is missing or not an array
     */
    public List<String> getStrings(String field) {
        JsonNode value = node.path(field);
        if (!value.isArray()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (JsonNode element : value) {
            result.add(element.asText());
        }
        return List.copyOf(result);
    }

    /** Returns the array of objects at the given field, or an empty list if missing / not an array. */
    public List<DidDocument> getObjects(String field) {
        JsonNode value = node.path(field);
        if (!value.isArray()) {
            return List.of();
        }
        List<DidDocument> result = new ArrayList<>();
        for (JsonNode element : value) {
            if (element.isObject()) {
                result.add(new DidDocument(element));
            }
        }
        return List.copyOf(result);
    }

    // -------------------------------------------------------------------------
    // Value coercion (on this node itself)
    // -------------------------------------------------------------------------

    /** Returns the text value of this node, or empty string if not textual. */
    public String asText() {
        return node.asText();
    }

    /** Returns the text value of this node, or {@code defaultValue} if missing / not textual. */
    public String asText(String defaultValue) {
        return node.isMissingNode() ? defaultValue : node.asText(defaultValue);
    }

    /** Returns the boolean value of this node, or {@code false} if missing / not boolean. */
    public boolean asBoolean() {
        return node.asBoolean();
    }

    /** Returns the boolean value of this node, or {@code defaultValue} if missing / not boolean. */
    public boolean asBoolean(boolean defaultValue) {
        return node.isMissingNode() ? defaultValue : node.asBoolean(defaultValue);
    }

    /** Returns the int value of this node, or {@code 0} if missing / not numeric. */
    public int asInt() {
        return node.asInt();
    }

    /** Returns the int value of this node, or {@code defaultValue} if missing / not numeric. */
    public int asInt(int defaultValue) {
        return node.isMissingNode() ? defaultValue : node.asInt(defaultValue);
    }

    // -------------------------------------------------------------------------
    // Navigation / introspection
    // -------------------------------------------------------------------------

    /** Returns {@code true} if this object has the given field. */
    public boolean has(String field) {
        return node.has(field);
    }

    /** Returns {@code true} if this node is a Jackson "missing" node. */
    public boolean isMissing() {
        return node.isMissingNode();
    }

    /** Returns {@code true} if this node is a JSON array. */
    public boolean isArray() {
        return node.isArray();
    }

    /** Returns {@code true} if this node is a JSON object. */
    public boolean isObject() {
        return node.isObject();
    }

    /**
     * Safe navigation: returns a {@code DidDocument} for the given field.
     * If the field does not exist, the returned wrapper's {@link #isMissing()}
     * will be {@code true}.
     */
    public DidDocument path(String field) {
        return new DidDocument(node.path(field));
    }

    /** Returns the elements of this array as a list of {@code DidDocument} wrappers. */
    public List<DidDocument> elements() {
        if (!node.isArray()) {
            return List.of();
        }
        List<DidDocument> result = new ArrayList<>();
        for (JsonNode element : node) {
            result.add(new DidDocument(element));
        }
        return List.copyOf(result);
    }

    // -------------------------------------------------------------------------
    // Copying
    // -------------------------------------------------------------------------

    /** Returns a deep copy of this document. */
    public DidDocument deepCopy() {
        return new DidDocument(node.deepCopy());
    }

    /**
     * Returns a mutable builder pre-populated with the fields of this document.
     * If this node is not an object, an empty builder is returned.
     */
    public Builder toBuilder() {
        if (!node.isObject()) {
            return builder();
        }
        return new Builder((ObjectNode) node.deepCopy());
    }

    /** Returns a copy of this object with the given field removed. */
    public DidDocument without(String field) {
        if (node.isObject()) {
            ObjectNode copy = (ObjectNode) node.deepCopy();
            copy.remove(field);
            return new DidDocument(copy);
        }
        return this;
    }

    // -------------------------------------------------------------------------
    // Serialization
    // -------------------------------------------------------------------------

    /** Returns this document as a compact JSON string. */
    public String toJson() {
        try {
            return MAPPER.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize DidDocument", e);
        }
    }

    @Override
    public String toString() {
        return toJson();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DidDocument that = (DidDocument) o;
        return node.equals(that.node);
    }

    @Override
    public int hashCode() {
        return node.hashCode();
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------

    /** Returns a new fluent builder. */
    public static Builder builder() {
        return new Builder();
    }

    /** Fluent builder for programmatic {@code DidDocument} construction. */
    public static final class Builder {
        private final ObjectNode node;

        private Builder() {
            this.node = MAPPER.createObjectNode();
        }

        private Builder(ObjectNode node) {
            this.node = node;
        }

        public Builder setString(String field, String value) {
            node.put(field, value);
            return this;
        }

        public Builder setBoolean(String field, boolean value) {
            node.put(field, value);
            return this;
        }

        public Builder setInt(String field, int value) {
            node.put(field, value);
            return this;
        }

        public Builder setObject(String field, DidDocument value) {
            node.set(field, value.node);
            return this;
        }

        public Builder setStrings(String field, List<String> values) {
            ArrayNode array = MAPPER.createArrayNode();
            for (String v : values) {
                array.add(v);
            }
            node.set(field, array);
            return this;
        }

        public Builder setObjects(String field, List<DidDocument> values) {
            ArrayNode array = MAPPER.createArrayNode();
            for (DidDocument v : values) {
                array.add(v.node);
            }
            node.set(field, array);
            return this;
        }

        /** Builds an immutable {@code DidDocument}. */
        public DidDocument build() {
            return new DidDocument(node.deepCopy());
        }
    }
}
