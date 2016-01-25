package de.dogcraft.ssltest.dns.rr;

import java.net.Inet4Address;
import java.net.InetAddress;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.IPv4;

public class A extends RR {

    private InetAddress ip4address;

    static {
        parserFormat.add(new NamedEntityContainer<IPv4>(IPv4.class, "ADDRESS"));
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "A";
    }

    @Override
    public String toTextualRData() {
        return ip4address.toString();
    }

    public InetAddress getIP4Address() {
        return ip4address;
    }

    public boolean setIP4Address(InetAddress ip4address) {
        if ( !(ip4address instanceof Inet4Address)) {
            return false;
        }

        this.ip4address = ip4address;
        return true;
    }

}
