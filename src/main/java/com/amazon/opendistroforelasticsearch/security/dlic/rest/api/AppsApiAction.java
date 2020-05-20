package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.nio.file.Path;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AppValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;

import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;

public class AppsApiAction extends PatchableResourceApiAction {

    @Inject
    public AppsApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                            final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    protected void registerHandlers(RestController controller, Settings settings) {
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/apps/{name}", this);
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/apps/", this);
        controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/apps/{name}", this);
        controller.registerHandler(Method.PUT, "/_opendistro/_security/api/apps/{name}", this);
        controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/apps/", this);
        controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/apps/{name}", this);
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.APPS;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(final RestRequest request, BytesReference ref, Object... param) {
        return new AppValidator(request, isSuperAdmin(), ref, this.settings, param);
    }

    @Override
    protected CType getConfigName() {
        return CType.APPS;
    }

    @Override
    protected String getResourceName() {
        return "app";
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.param("name");
    }

}
