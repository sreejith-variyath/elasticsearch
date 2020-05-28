package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Joiner;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

public class AppConfigurationValidator extends AbstractConfigurationValidator {

    protected final Logger logger = LogManager.getLogger(this.getClass());

    protected ErrorType errorType = ErrorType.NONE;
    PrivilegesEvaluator evaluator;

    public AppConfigurationValidator(RestRequest request, BytesReference ref, Settings esSettings, PrivilegesEvaluator evaluator, Object... param) {
        super(request, ref, esSettings, param);
        this.evaluator = evaluator;
    }

    @Override
    public JsonNode getContentAsNode() {
        return super.getContentAsNode();
    }

    /**
     * @return false if validation fails
     */
    @Override
    public boolean validate() {
        if (!super.validate()) {
            return false;
        }

        boolean valid = true;

        if (this.content != null && this.content.length() > 0) {

            final ReadContext ctx = JsonPath.parse(this.content.utf8ToString());
            String tenantName = ctx.read("tenant");

            logger.info(" Logging the request Content {} ", this.content.utf8ToString());
            logger.info(" Tenant name  {} ", tenantName);

            Set<String> tenants = evaluator.getAllConfiguredTenantNames();
            if (!tenants.contains(tenantName)) {
                valid = false;
                this.errorType = ErrorType.INVALID_TENANT;
            }

        }
        return valid;
    }

    @Override
    public XContentBuilder errorsAsXContent(RestChannel channel) {
        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            if (lastException != null) {
                builder.field("details", lastException.toString());
            }
            switch (errorType) {
                case NONE:
                    builder.field("status", "error");
                    builder.field("reason", errorType.getMessage());
                    break;
                case INVALID_TENANT:
                    builder.field("status", "error");
                    builder.field("reason", errorType.getMessage());
                    break;
                case INVALID_CONFIGURATION:
                    builder.field("status", "error");
                    builder.field("reason", AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage());
                    addErrorMessage(builder, INVALID_KEYS_KEY, invalidKeys);
                    addErrorMessage(builder, MISSING_MANDATORY_KEYS_KEY, missingMandatoryKeys);
                    addErrorMessage(builder, MISSING_MANDATORY_OR_KEYS_KEY, missingMandatoryKeys);
                    break;
                case INVALID_PASSWORD:
                    builder.field("status", "error");
                    builder.field("reason", esSettings.get(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE,
                            "Password does not match minimum criteria"));
                    break;
                case WRONG_DATATYPE:
                    builder.field("status", "error");
                    builder.field("reason", AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage());
                    for (Map.Entry<String, String> entry : wrongDatatypes.entrySet()) {
                        builder.field(entry.getKey(), entry.getValue());
                    }
                    break;
                default:
                    builder.field("status", "error");
                    builder.field("reason", errorType.getMessage());

            }
            builder.endObject();
            return builder;
        } catch (IOException ex) {
            log.error("Cannot build error settings", ex);
            return null;
        }
    }

    private void addErrorMessage(final XContentBuilder builder, final String message, final Set<String> keys) throws IOException {
        if (!keys.isEmpty()) {
            builder.startObject(message);
            builder.field("keys", Joiner.on(",").join(keys.toArray(new String[0])));
            builder.endObject();
        }
    }

    public static enum ErrorType {
        NONE("ok"), INVALID_CONFIGURATION("Invalid configuration"), INVALID_PASSWORD("Invalid password"), WRONG_DATATYPE("Wrong datatype"),
        BODY_NOT_PARSEABLE("Could not parse content of request."), PAYLOAD_NOT_ALLOWED("Request body not allowed for this action."),
        PAYLOAD_MANDATORY("Request body required for this action."), SECURITY_NOT_INITIALIZED("Security index not initialized"), INVALID_TENANT("Invalid Tenant specified for the app");
        private String message;

        private ErrorType(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }


    }
}
