package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.Text;

public class HINFO extends RR {

    private String cpu;

    private String os;

    static {
        parserFormat.add(new NamedEntityContainer<Text>(Text.class, "CPU"));
        parserFormat.add(new NamedEntityContainer<Text>(Text.class, "OS"));
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "HINFO";
    }

    public String getCPU() {
        return cpu;
    }

    public void setCPU(String cpu) {
        this.cpu = cpu;
    }

    public String getOS() {
        return os;
    }

    public void setOS(String os) {
        this.os = os;
    }

}
