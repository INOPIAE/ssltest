package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.Int16;
import de.dogcraft.ssltest.dns.encoding.blocks.Int32;

public class LOC extends RR {

    private Int16 version;

    private Int16 size;

    private Int16 precisionHorizontal;

    private Int16 precisionVertical;

    private Int32 latitude;

    private Int32 longitude;

    private Int32 altitude;

    static {
        parserFormat.add(new NamedEntityContainer<Int16>(Int16.class, "VERSION"));
        parserFormat.add(new NamedEntityContainer<Int16>(Int16.class, "SIZE"));
        parserFormat.add(new NamedEntityContainer<Int16>(Int16.class, "HORIZ_PRE"));
        parserFormat.add(new NamedEntityContainer<Int16>(Int16.class, "VORT_PRE"));

        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "LATITUDE"));
        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "LONGITUDE"));
        parserFormat.add(new NamedEntityContainer<Int32>(Int32.class, "ALTITUDE"));
    }

    @Override
    public boolean isWellKnown() {
        return false;
    }

    @Override
    public String getTypeName() {
        return "LOC";
    }

    public Int16 getVersion() {
        return version;
    }

    public void setVersion(Int16 version) {
        this.version = version;
    }

    public Int16 getSize() {
        return size;
    }

    public void setSize(Int16 size) {
        this.size = size;
    }

    public Int16 getPrecisionHorizontal() {
        return precisionHorizontal;
    }

    public void setPrecisionHorizontal(Int16 precisionHorizontal) {
        this.precisionHorizontal = precisionHorizontal;
    }

    public Int16 getPrecisionVertical() {
        return precisionVertical;
    }

    public void setPrecisionVertical(Int16 precisionVertical) {
        this.precisionVertical = precisionVertical;
    }

    public Int32 getLatitude() {
        return latitude;
    }

    public void setLatitude(Int32 latitude) {
        this.latitude = latitude;
    }

    public Int32 getLongitude() {
        return longitude;
    }

    public void setLongitude(Int32 longitude) {
        this.longitude = longitude;
    }

    public Int32 getAltitude() {
        return altitude;
    }

    public void setAltitude(Int32 altitude) {
        this.altitude = altitude;
    }

}
