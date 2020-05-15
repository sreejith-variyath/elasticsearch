package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.DomainValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

import java.nio.file.Path;

/**
 * Created by sreejith on 5/12/2020.
 */
public class DomainApiAction extends PatchableResourceApiAction {

    @Inject
    public DomainApiAction(Settings settings, Path configPath, RestController controller, Client client, AdminDNs adminDNs, ConfigurationRepository cl,
                           ClusterService cs, PrincipalExtractor principalExtractor, PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    /**
     * Abstract function to register handlers for API actions
     *
     * @param controller rest controller
     * @param settings   settings configuration
     */
    @Override
    protected void registerHandlers(RestController controller, Settings settings) {
        controller.registerHandler(RestRequest.Method.PUT, "/_opendistro/_security/api/domain/{name}", this);
    }


    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.DOMAIN;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new DomainValidator(request, isSuperAdmin(), ref, this.settings, params);
    }

    @Override
    protected String getResourceName() {
        return "domain";
    }

    @Override
    protected CType getConfigName() {
        return CType.DOMAIN;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.param("name");
    }


     /*  @Override
    protected AbstractConfigurationValidator postProcessApplyPatchResult(RestChannel channel, RestRequest request, JsonNode existingResourceAsJsonNode, JsonNode updatedResourceAsJsonNode, String resourceName) {
        return super.postProcessApplyPatchResult(channel, request, existingResourceAsJsonNode, updatedResourceAsJsonNode, resourceName);
    }

 @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        super.handleApiRequest(channel, request, client);
    }*/
}
