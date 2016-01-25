package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.DNSName;

public class PTR extends RR {

    private DNSName ptrdname;

    static {
        parserFormat.add(new NamedEntityContainer<DNSName>(DNSName.class, "PTRDNAME"));
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "PTR";
    }

    public DNSName getPTRDName() {
        return ptrdname;
    }

    public void setPTRDName(DNSName ptrdname) {
        this.ptrdname = ptrdname;
    }

}
