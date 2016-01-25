package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.DNSName;

public class CNAME extends RR {

    private DNSName cname;

    static {
        parserFormat.add(new NamedEntityContainer<DNSName>(DNSName.class, "CNAME"));
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "CNAME";
    }

    public DNSName getCName() {
        return cname;
    }

    public void setCName(DNSName cname) {
        this.cname = cname;
    }

}
