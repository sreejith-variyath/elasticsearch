package com.amazon.opendistroforelasticsearch.security.rest;

import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.*;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;

import static org.elasticsearch.rest.RestRequest.Method.GET;

/**
 * Created by sreejith on 5/11/2020.
 */
public class CustomInfoAction extends BaseRestHandler {

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;
    private final ClusterService clusterService;
    private final AdminDNs adminDns;

    public CustomInfoAction(final Settings settings, final RestController controller,
                            final PrivilegesEvaluator evaluator, final ThreadPool threadPool, final ClusterService clusterService, final AdminDNs adminDns) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.evaluator = evaluator;
        this.clusterService = clusterService;
        this.adminDns = adminDns;
        controller.registerHandler(GET, "/_opendistro/_security/customInfo", this);
    }

    @Override
    public String getName() {
            return "Custom Info Action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest restRequest, NodeClient nodeClient) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder(); //NOSONAR
                BytesRestResponse response = null;
                try {
                    final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    builder.startObject();
                    builder.field("info", "This is a custom action");
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    log.error(e1.toString(),e1);
                    builder = channel.newBuilder(); //NOSONAR
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if(builder != null) {
                        builder.close();
                    }
                }
                channel.sendResponse(response);
            }
        };
    }
}
