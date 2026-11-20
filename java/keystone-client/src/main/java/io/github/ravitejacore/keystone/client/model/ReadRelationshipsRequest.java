package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request payload for POST /v1/relationships/read.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ReadRelationshipsRequest(
    @JsonProperty("object_type") String objectType,
    @JsonProperty("object_id") String objectId,
    @JsonProperty("relation") String relation,
    @JsonProperty("subject_type") String subjectType,
    @JsonProperty("subject_id") String subjectId,
    @JsonProperty("subject_relation") String subjectRelation,
    @JsonProperty("limit") Integer limit,
    @JsonProperty("continuation_token") String continuationToken,
    @JsonProperty("consistency") Consistency consistency
) {
    public static class Builder {
        private String objectType;
        private String objectId;
        private String relation;
        private String subjectType;
        private String subjectId;
        private String subjectRelation;
        private Integer limit;
        private String continuationToken;
        private Consistency consistency;

        public Builder object(String type, String id) {
            this.objectType = type;
            this.objectId = id;
            return this;
        }

        public Builder relation(String relation) {
            this.relation = relation;
            return this;
        }

        public Builder subject(String type, String id) {
            this.subjectType = type;
            this.subjectId = id;
            return this;
        }

        public Builder subject(String type, String id, String relation) {
            this.subjectType = type;
            this.subjectId = id;
            this.subjectRelation = relation;
            return this;
        }

        public Builder limit(int limit) {
            this.limit = limit;
            return this;
        }

        public Builder continuationToken(String token) {
            this.continuationToken = token;
            return this;
        }

        public Builder consistency(Consistency consistency) {
            this.consistency = consistency;
            return this;
        }

        public ReadRelationshipsRequest build() {
            return new ReadRelationshipsRequest(
                objectType, objectId, relation,
                subjectType, subjectId, subjectRelation,
                limit, continuationToken, consistency
            );
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
