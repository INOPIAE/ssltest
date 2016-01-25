package de.dogcraft.ssltest.dns.rr;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.IPv6;

public class AAAA extends RR {

    private InetAddress ip6address;

    static {
        parserFormat.add(new NamedEntityContainer<IPv6>(IPv6.class, "ADDRESS"));
    }

    @Override
    protected boolean parseRData(byte[] rdata, boolean setState) {
        if (rdata.length != 16) {
            return false;
        }

        InetAddress address;
        try {
            address = InetAddress.getByAddress(rdata);
        } catch (UnknownHostException e) {
            return false;
        }

        if (setState) {
            setIP6Address(address);
        }

        return true;
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "AAAA";
    }

    @Override
    public boolean fromTextualRData(String textual, String origin) {
        try {
            this.setIP6Address(Inet6Address.getByName(textual));
        } catch (UnknownHostException e) {
            return false;
        }

        return true;
    }

    @Override
    public String toTextualRData() {
        return ip6address.toString();
    }

    public InetAddress getIP6Address() {
        return ip6address;
    }

    public boolean setIP6Address(InetAddress ip6address) {
        if ( !(ip6address instanceof Inet6Address)) {
            return false;
        }

        this.ip6address = ip6address;

        this.rdata = this.ip6address.getAddress();
        return true;
    }

}
