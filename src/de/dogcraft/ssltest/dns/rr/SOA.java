package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.DNSName;
import de.dogcraft.ssltest.dns.encoding.blocks.Int32;

public class SOA extends RR {

    private DNSName mname;

    private DNSName rname;

    private long serial;

    private long refresh;

    private long retry;

    private long expire;

    private long minimum;

    static {
        parserFormat.add(new NamedEntityContainer<DNSName>(DNSName.class, "MNAME"));
        parserFormat.add(new NamedEntityContainer<DNSName>(DNSName.class, "RNAME"));

        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "SERIAL"));
        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "REFRESH"));
        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "RETRY"));
        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "EXPIRE"));
        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "MINIMUM"));
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "SOA";
    }

    public DNSName getMname() {
        return mname;
    }

    public void setMname(DNSName mname) {
        this.mname = mname;
    }

    public DNSName getRname() {
        return rname;
    }

    public void setRname(DNSName rname) {
        this.rname = rname;
    }

    public long getSerial() {
        return serial;
    }

    public void setSerial(long serial) {
        this.serial = serial;
    }

    public long getRefresh() {
        return refresh;
    }

    public void setRefresh(long refresh) {
        this.refresh = refresh;
    }

    public long getRetry() {
        return retry;
    }

    public void setRetry(long retry) {
        this.retry = retry;
    }

    public long getExpire() {
        return expire;
    }

    public void setExpire(long expire) {
        this.expire = expire;
    }

    public long getMinimum() {
        return minimum;
    }

    public void setMinimum(long minimum) {
        this.minimum = minimum;
    }

}
