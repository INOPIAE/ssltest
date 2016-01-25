package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.DNSName;
import de.dogcraft.ssltest.dns.encoding.blocks.Int16;

public class MX extends RR {

    private int preference;

    private DNSName exchange;

    static {
        parserFormat.add(new NamedEntityContainer<Int16>(Int16.class, "PREFERENCE"));
        parserFormat.add(new NamedEntityContainer<DNSName>(DNSName.class, "EXCHANGE"));
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "MX";
    }

    public int getPreference() {
        return preference;
    }

    public void setPreference(int preference) {
        this.preference = preference;
    }

    public DNSName getExchange() {
        return exchange;
    }

    public void setExchange(DNSName exchange) {
        this.exchange = exchange;
    }

}
