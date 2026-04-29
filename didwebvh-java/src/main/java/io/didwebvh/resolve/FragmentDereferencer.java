package io.didwebvh.resolve;

import com.fasterxml.jackson.databind.JsonNode;
import io.didwebvh.exception.DidNotFoundException;

import java.util.List;

/**
 * Dereferences a DID URL fragment within a resolved DID document.
 *
 * <p>Given a fragment string (e.g. {@code "#key-1"}) and the resolved DID document, this class
 * searches the well-known DID document sub-maps for an element whose {@code id} equals
 * {@code document.id + fragment}. Matches are searched in declaration order across:
 * {@code verificationMethod}, {@code authentication}, {@code assertionMethod},
 * {@code keyAgreement}, {@code capabilityInvocation}, {@code capabilityDelegation},
 * {@code service}.
 */
final class FragmentDereferencer {

    private static final List<String> DEREFERENCEABLE_FIELDS = List.of(
            "verificationMethod",
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
            "service"
    );

    private FragmentDereferencer() {}

    /**
     * Finds the element in the DID document whose {@code id} matches
     * {@code document["id"] + fragment}.
     *
     * @param document the fully resolved DID document ({@code JsonNode})
     * @param fragment the fragment string including the leading {@code #} (e.g. {@code "#key-1"})
     * @return the matching {@link JsonNode} (typically a verification method or service object)
     * @throws DidNotFoundException if no element with a matching {@code id} is found
     */
    static JsonNode dereference(JsonNode document, String fragment) {
        String docId = document.path("id").asText("");
        String targetId = docId + fragment;

        for (String field : DEREFERENCEABLE_FIELDS) {
            JsonNode array = document.path(field);
            if (!array.isArray()) continue;
            for (JsonNode element : array) {
                if (element.isObject()) {
                    String elementId = element.path("id").asText(null);
                    if (targetId.equals(elementId)) {
                        return element;
                    }
                }
            }
        }

        throw new DidNotFoundException("Fragment '" + fragment + "' not found in DID document");
    }
}
