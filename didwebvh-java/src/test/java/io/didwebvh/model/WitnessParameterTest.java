package io.didwebvh.model;

import io.didwebvh.exception.LogValidationException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link WitnessParameter#validate()}.
 */
class WitnessParameterTest {

    private static final String DID_KEY_A = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    private static final String DID_KEY_B = "did:key:z6MkhGZ2Q4wDGNhRAFKwcYcAp7GKdcQb1hkKmHq9UQCB5kN";

    private static WitnessParameter.WitnessEntry entry(String id) {
        return new WitnessParameter.WitnessEntry(id);
    }

    // -------------------------------------------------------------------------
    // Empty / null configurations are always valid
    // -------------------------------------------------------------------------

    @Nested
    class EmptyOrNull {

        @Test
        void null_witnesses_isValid() {
            WitnessParameter p = new WitnessParameter(null, null);
            assertThatCode(p::validate).doesNotThrowAnyException();
        }

        @Test
        void empty_witnesses_list_isValid() {
            WitnessParameter p = new WitnessParameter(null, List.of());
            assertThatCode(p::validate).doesNotThrowAnyException();
        }
    }

    // -------------------------------------------------------------------------
    // Threshold rules
    // -------------------------------------------------------------------------

    @Nested
    class ThresholdRules {

        @Test
        void threshold_one_of_one_isValid() {
            WitnessParameter p = new WitnessParameter(1, List.of(entry(DID_KEY_A)));
            assertThatCode(p::validate).doesNotThrowAnyException();
        }

        @Test
        void threshold_two_of_two_isValid() {
            WitnessParameter p = new WitnessParameter(2, List.of(entry(DID_KEY_A), entry(DID_KEY_B)));
            assertThatCode(p::validate).doesNotThrowAnyException();
        }

        @Test
        void threshold_one_of_two_isValid() {
            WitnessParameter p = new WitnessParameter(1, List.of(entry(DID_KEY_A), entry(DID_KEY_B)));
            assertThatCode(p::validate).doesNotThrowAnyException();
        }

        @Test
        void threshold_null_throws() {
            WitnessParameter p = new WitnessParameter(null, List.of(entry(DID_KEY_A)));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("threshold");
        }

        @Test
        void threshold_zero_throws() {
            WitnessParameter p = new WitnessParameter(0, List.of(entry(DID_KEY_A)));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("threshold");
        }

        @Test
        void threshold_exceeds_witness_count_throws() {
            // 2 witnesses but threshold = 3
            WitnessParameter p = new WitnessParameter(3, List.of(entry(DID_KEY_A), entry(DID_KEY_B)));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("threshold");
        }

        @Test
        void threshold_negative_throws() {
            WitnessParameter p = new WitnessParameter(-1, List.of(entry(DID_KEY_A)));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("threshold");
        }
    }

    // -------------------------------------------------------------------------
    // did:key format rules
    // -------------------------------------------------------------------------

    @Nested
    class DidKeyFormat {

        @Test
        void did_key_format_isValid() {
            WitnessParameter p = new WitnessParameter(1, List.of(entry(DID_KEY_A)));
            assertThatCode(p::validate).doesNotThrowAnyException();
        }

        @Test
        void did_web_format_throws() {
            WitnessParameter p = new WitnessParameter(1,
                    List.of(entry("did:web:example.com")));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("did:key");
        }

        @Test
        void did_webvh_format_throws() {
            WitnessParameter p = new WitnessParameter(1,
                    List.of(entry("did:webvh:QmXxx:example.com")));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("did:key");
        }

        @Test
        void bare_multikey_without_did_key_prefix_throws() {
            WitnessParameter p = new WitnessParameter(1,
                    List.of(entry("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("did:key");
        }

        @Test
        void null_id_throws() {
            WitnessParameter p = new WitnessParameter(1, List.of(entry(null)));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class);
        }

        @Test
        void blank_id_throws() {
            WitnessParameter p = new WitnessParameter(1, List.of(entry("   ")));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class);
        }
    }

    // -------------------------------------------------------------------------
    // Uniqueness rules
    // -------------------------------------------------------------------------

    @Nested
    class Uniqueness {

        @Test
        void two_distinct_witnesses_isValid() {
            WitnessParameter p = new WitnessParameter(1, List.of(entry(DID_KEY_A), entry(DID_KEY_B)));
            assertThatCode(p::validate).doesNotThrowAnyException();
        }

        @Test
        void duplicate_witness_id_throws() {
            WitnessParameter p = new WitnessParameter(1,
                    List.of(entry(DID_KEY_A), entry(DID_KEY_A)));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("Duplicate");
        }

        @Test
        void three_witnesses_with_one_duplicate_throws() {
            WitnessParameter p = new WitnessParameter(2,
                    List.of(entry(DID_KEY_A), entry(DID_KEY_B), entry(DID_KEY_A)));
            assertThatThrownBy(p::validate)
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("Duplicate");
        }
    }

    // -------------------------------------------------------------------------
    // Integration: validation triggered through Parameters.validate()
    // -------------------------------------------------------------------------

    @Nested
    class ThroughParametersValidate {

        private static final String SCID = "QmVk3TBLNriSdFDVXDDHLsxRNiGgS96v5kDqe8hMsFUB3";
        private static final String KEY = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        @Test
        void genesis_with_valid_witness_passes() {
            WitnessParameter witness = new WitnessParameter(1, List.of(entry(DID_KEY_A)));
            Parameters genesis = new Parameters(
                    "did:webvh:1.0", SCID, List.of(KEY),
                    null, null, null, null, witness, null);
            assertThatCode(() -> genesis.validate(null)).doesNotThrowAnyException();
        }

        @Test
        void genesis_with_non_did_key_witness_throws() {
            WitnessParameter bad = new WitnessParameter(1,
                    List.of(entry("did:web:example.com")));
            Parameters genesis = new Parameters(
                    "did:webvh:1.0", SCID, List.of(KEY),
                    null, null, null, null, bad, null);
            assertThatThrownBy(() -> genesis.validate(null))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("did:key");
        }

        @Test
        void update_introducing_duplicate_witness_throws() {
            Parameters genesisEffective = new Parameters(
                    "did:webvh:1.0", SCID, List.of(KEY),
                    null, null, null, null, null, null).validate(null);

            WitnessParameter bad = new WitnessParameter(1,
                    List.of(entry(DID_KEY_A), entry(DID_KEY_A)));
            Parameters update = new Parameters(
                    null, null, null, null, null, null, null, bad, null);
            assertThatThrownBy(() -> update.validate(genesisEffective))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("Duplicate");
        }

        @Test
        void update_with_threshold_exceeding_witnesses_throws() {
            Parameters genesisEffective = new Parameters(
                    "did:webvh:1.0", SCID, List.of(KEY),
                    null, null, null, null, null, null).validate(null);

            WitnessParameter bad = new WitnessParameter(5,
                    List.of(entry(DID_KEY_A), entry(DID_KEY_B)));
            Parameters update = new Parameters(
                    null, null, null, null, null, null, null, bad, null);
            assertThatThrownBy(() -> update.validate(genesisEffective))
                    .isInstanceOf(LogValidationException.class)
                    .hasMessageContaining("threshold");
        }
    }
}
