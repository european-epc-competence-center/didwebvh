package io.didwebvh.model;

import io.didwebvh.DidWebVhConstants;
import io.didwebvh.exception.LogValidationException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link Parameters#validate} and {@link Parameters#diff}.
 */
class ParametersTest {

    private static final String SCID = "QmVk3TBLNriSdFDVXDDHLsxRNiGgS96v5kDqe8hMsFUB3";
    private static final String KEY1 = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    private static final String KEY2 = "z6MkhGZ2Q4wDGNhRAFKwcYcAp7GKdcQb1hkKmHq9UQCB5kN";
    private static final String KEY1_HASH = "QmHashKey1";
    private static final String KEY2_HASH = "QmHashKey2";

    // -------------------------------------------------------------------------
    // Genesis entry validation
    // -------------------------------------------------------------------------

    @Test
    void validate_genesis_minimalValid() {
        Parameters genesis = new Parameters(
                DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                null, null, null, null, null, null);

        Parameters effective = genesis.validate(null);

        assertThat(effective.method()).isEqualTo(DidWebVhConstants.METHOD_V1_0);
        assertThat(effective.scid()).isEqualTo(SCID);
        assertThat(effective.updateKeys()).containsExactly(KEY1);
        // defaults applied
        assertThat(effective.nextKeyHashes()).isEmpty();
        assertThat(effective.portable()).isFalse();
        assertThat(effective.deactivated()).isFalse();
        assertThat(effective.ttl()).isEqualTo(DidWebVhConstants.DEFAULT_TTL_SECONDS);
        assertThat(effective.witness()).isNull();
        assertThat(effective.watchers()).isEmpty();
    }

    @Test
    void validate_genesis_missingMethod_throws() {
        Parameters p = new Parameters(null, SCID, List.of(KEY1),
                null, null, null, null, null, null);
        assertThatThrownBy(() -> p.validate(null))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("method");
    }

    @Test
    void validate_genesis_wrongMethod_throws() {
        Parameters p = new Parameters("did:webvh:0.5", SCID, List.of(KEY1),
                null, null, null, null, null, null);
        assertThatThrownBy(() -> p.validate(null))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("method");
    }

    @Test
    void validate_genesis_missingScid_throws() {
        Parameters p = new Parameters(DidWebVhConstants.METHOD_V1_0, null, List.of(KEY1),
                null, null, null, null, null, null);
        assertThatThrownBy(() -> p.validate(null))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("scid");
    }

    @Test
    void validate_genesis_missingUpdateKeys_throws() {
        Parameters p = new Parameters(DidWebVhConstants.METHOD_V1_0, SCID, null,
                null, null, null, null, null, null);
        assertThatThrownBy(() -> p.validate(null))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("updateKeys");
    }

    @Test
    void validate_genesis_emptyUpdateKeys_throws() {
        Parameters p = new Parameters(DidWebVhConstants.METHOD_V1_0, SCID, List.of(),
                null, null, null, null, null, null);
        assertThatThrownBy(() -> p.validate(null))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("updateKeys");
    }

    @Test
    void validate_genesis_withPreRotation_returnsEffective() {
        Parameters genesis = new Parameters(
                DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                List.of(KEY1_HASH), true, null, 600, null, List.of("https://watcher.example.com"));

        Parameters effective = genesis.validate(null);

        assertThat(effective.nextKeyHashes()).containsExactly(KEY1_HASH);
        assertThat(effective.portable()).isTrue();
        assertThat(effective.ttl()).isEqualTo(600);
        assertThat(effective.watchers()).containsExactly("https://watcher.example.com");
    }

    // -------------------------------------------------------------------------
    // Subsequent entry validation
    // -------------------------------------------------------------------------

    @Test
    void validate_subsequent_noChanges_inheritsAllFields() {
        Parameters effective1 = genesisEffective();

        Parameters update = new Parameters(null, null, null, null, null, null, null, null, null);
        Parameters effective2 = update.validate(effective1);

        assertThat(effective2.method()).isEqualTo(effective1.method());
        assertThat(effective2.updateKeys()).isEqualTo(effective1.updateKeys());
        assertThat(effective2.nextKeyHashes()).isEqualTo(effective1.nextKeyHashes());
        assertThat(effective2.portable()).isEqualTo(effective1.portable());
        assertThat(effective2.deactivated()).isEqualTo(effective1.deactivated());
        assertThat(effective2.ttl()).isEqualTo(effective1.ttl());
        // scid is never inherited
        assertThat(effective2.scid()).isNull();
    }

    @Test
    void validate_subsequent_rotateKeys() {
        Parameters effective1 = genesisEffective();

        Parameters update = new Parameters(null, null, List.of(KEY2), null, null, null, null, null, null);
        Parameters effective2 = update.validate(effective1);

        assertThat(effective2.updateKeys()).containsExactly(KEY2);
    }

    @Test
    void validate_subsequent_scidPresent_throws() {
        Parameters effective1 = genesisEffective();
        Parameters update = new Parameters(null, SCID, List.of(KEY2), null, null, null, null, null, null);
        assertThatThrownBy(() -> update.validate(effective1))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("scid");
    }

    @Test
    void validate_subsequent_portableSetTrueAfterFalse_throws() {
        // portable was false (default) in genesis, cannot flip to true later
        Parameters effective1 = genesisEffective(); // portable = false
        Parameters update = new Parameters(null, null, null, null, Boolean.TRUE, null, null, null, null);
        assertThatThrownBy(() -> update.validate(effective1))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("portable");
    }

    @Test
    void validate_subsequent_portableSetFalseWhenTrue_throws() {
        Parameters genesis = new Parameters(
                DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                null, Boolean.TRUE, null, null, null, null);
        Parameters effective1 = genesis.validate(null);

        Parameters update = new Parameters(null, null, null, null, Boolean.FALSE, null, null, null, null);
        assertThatThrownBy(() -> update.validate(effective1))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("portable");
    }

    @Test
    void validate_subsequent_portableRepeatedTrue_allowed() {
        Parameters genesis = new Parameters(
                DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                null, Boolean.TRUE, null, null, null, null);
        Parameters effective1 = genesis.validate(null);

        // Repeating the same value is fine
        Parameters update = new Parameters(null, null, List.of(KEY2), null, Boolean.TRUE, null, null, null, null);
        Parameters effective2 = update.validate(effective1);
        assertThat(effective2.portable()).isTrue();
    }

    @Test
    void validate_preRotationActive_missingUpdateKeys_throws() {
        Parameters genesis = new Parameters(
                DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                List.of(KEY1_HASH), null, null, null, null, null);
        Parameters effective1 = genesis.validate(null);
        assertThat(effective1.isPreRotationActive()).isTrue();

        // Update omits updateKeys — invalid while pre-rotation is active
        Parameters update = new Parameters(null, null, null, List.of(KEY2_HASH), null, null, null, null, null);
        assertThatThrownBy(() -> update.validate(effective1))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("updateKeys");
    }

    @Test
    void validate_preRotationActive_missingNextKeyHashes_throws() {
        Parameters genesis = new Parameters(
                DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                List.of(KEY1_HASH), null, null, null, null, null);
        Parameters effective1 = genesis.validate(null);

        // Update omits nextKeyHashes — invalid while pre-rotation is active
        Parameters update = new Parameters(null, null, List.of(KEY2), null, null, null, null, null, null);
        assertThatThrownBy(() -> update.validate(effective1))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("nextKeyHashes");
    }

    @Test
    void validate_deactivated_previouslyDeactivated_throws() {
        Parameters effective1 = genesisEffective();
        Parameters deactivate = new Parameters(null, null, null, null, null, Boolean.TRUE, null, null, null);
        Parameters effectiveDeactivated = deactivate.validate(effective1);
        assertThat(effectiveDeactivated.isDeactivated()).isTrue();

        // No further entries allowed after deactivation
        Parameters next = new Parameters(null, null, List.of(KEY2), null, null, null, null, null, null);
        assertThatThrownBy(() -> next.validate(effectiveDeactivated))
                .isInstanceOf(LogValidationException.class)
                .hasMessageContaining("deactivated");
    }

    // -------------------------------------------------------------------------
    // diff
    // -------------------------------------------------------------------------

    @Test
    void diff_noChanges_allNull() {
        Parameters effective = genesisEffective();
        Parameters delta = effective.diff(effective);

        assertThat(delta.method()).isNull();
        assertThat(delta.scid()).isNull();
        assertThat(delta.updateKeys()).isNull();
        assertThat(delta.nextKeyHashes()).isNull();
        assertThat(delta.portable()).isNull();
        assertThat(delta.deactivated()).isNull();
        assertThat(delta.ttl()).isNull();
        assertThat(delta.witness()).isNull();
        assertThat(delta.watchers()).isNull();
    }

    @Test
    void diff_keyRotation_onlyUpdateKeysSet() {
        Parameters effective1 = genesisEffective();
        Parameters effective2 = new Parameters(
                effective1.method(), null, List.of(KEY2), effective1.nextKeyHashes(),
                effective1.portable(), effective1.deactivated(), effective1.ttl(),
                effective1.witness(), effective1.watchers());

        Parameters delta = effective2.diff(effective1);

        assertThat(delta.updateKeys()).containsExactly(KEY2);
        assertThat(delta.method()).isNull();
        assertThat(delta.scid()).isNull();
        assertThat(delta.nextKeyHashes()).isNull();
    }

    @Test
    void diff_scidNeverIncluded() {
        // Even if scid values somehow differ, diff must not emit scid
        Parameters with = new Parameters(DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                null, null, null, null, null, null).validate(null);
        Parameters without = genesisEffective(); // scid is set in both effective params

        Parameters delta = with.diff(without);
        assertThat(delta.scid()).isNull();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static Parameters genesisEffective() {
        Parameters genesis = new Parameters(
                DidWebVhConstants.METHOD_V1_0, SCID, List.of(KEY1),
                null, null, null, null, null, null);
        return genesis.validate(null);
    }
}
