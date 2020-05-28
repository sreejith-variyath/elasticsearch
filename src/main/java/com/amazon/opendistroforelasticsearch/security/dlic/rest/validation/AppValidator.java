package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;



import com.amazon.opendistroforelasticsearch.security.dlic.rest.api.RestApiPrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import java.util.List;
import java.util.Set;

public class AppValidator extends AppConfigurationValidator {

    protected final Logger logger = LogManager.getLogger(this.getClass());

    private final PrivilegesEvaluator evaluator;
    ErrorType errorType = ErrorType.NONE;

    public AppValidator(final RestRequest request, boolean isSuperAdmin, BytesReference ref, final Settings esSettings,PrivilegesEvaluator evaluator, Object... param) {
        super(request, ref, esSettings, evaluator,param);
        this.payloadMandatory = false;
        allowedKeys.put("description", DataType.STRING);
        allowedKeys.put("tenant", DataType.STRING);
        if (isSuperAdmin) allowedKeys.put("reserved", DataType.BOOLEAN);
        this.evaluator = evaluator;
    }

    /**
     * @return false if validation fails
     */
    @Override
    public boolean validate() {
        return super.validate();
    }
}
