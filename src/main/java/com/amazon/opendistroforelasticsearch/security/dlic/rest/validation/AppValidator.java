package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;



import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

public class AppValidator extends AbstractConfigurationValidator {

    public AppValidator(final RestRequest request, boolean isSuperAdmin, BytesReference ref, final Settings esSettings, Object... param) {
        super(request, ref, esSettings, param);
        this.payloadMandatory = false;
        allowedKeys.put("description", DataType.STRING);
        allowedKeys.put("tenant", DataType.STRING);
        if (isSuperAdmin) allowedKeys.put("reserved", DataType.BOOLEAN);
    }

}
