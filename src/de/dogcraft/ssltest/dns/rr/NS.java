package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.DNSName;

public class NS extends RR {

    private DNSName nsdname;

    static {
        parserFormat.add(new NamedEntityContainer<DNSName>(DNSName.class, "NSDNAME"));
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "NS";
    }

    public DNSName getNSDName() {
        return nsdname;
    }

    public void setNSDName(DNSName nsdname) {
        this.nsdname = nsdname;
    }

}
