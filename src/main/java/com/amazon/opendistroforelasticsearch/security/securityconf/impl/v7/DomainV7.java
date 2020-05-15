package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.StaticDefinable;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by sreejith on 5/12/2020.
 */
public class DomainV7 implements Hideable,StaticDefinable {

    private boolean reserved;
    private boolean hidden;
    @JsonProperty(value = "static")
    private boolean _static;
    private String description;

    @Override
    public boolean isHidden() {
        return hidden;
    }
    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }
    @Override
    public boolean isReserved() {
        return reserved;
    }
    public void setReserved(boolean reserved) {
        this.reserved = reserved;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }

    @JsonProperty(value = "static")
    public boolean isStatic() {
        return _static;
    }
    @JsonProperty(value = "static")
    public void setStatic(boolean _static) {
        this._static = _static;
    }
    @Override
    public String toString() {
        return "DomainV7 [reserved=" + reserved + ", hidden=" + hidden + ",description=" + description + "]";
    }


}
