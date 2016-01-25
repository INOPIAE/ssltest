package de.dogcraft.ssltest.dns;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.StringJoiner;

public class RDataCoder {

    public static String readDNSName(InputStream is) throws IOException {
        StringJoiner sj = new StringJoiner(".");

        String part;
        do {
            part = readDNSLabel(is);

            if ( !part.isEmpty()) {
                sj.add(part);
            }
        } while ( !part.isEmpty());

        return sj.toString();
    }

    public static void writeDNSName(OutputStream os, String dnsname) throws IOException {
        String[] split = dnsname.split("\\.");

        for (String s : split) {
            if ( !s.isEmpty()) {
                writeDNSLabel(os, s);
            }
        }

        // Final empty label ...
        os.write(0);
    }

    public static String readDNSLabel(InputStream is) throws IOException {
        int len = is.read();
        if ( -1 == len) {
            throw new IOException("no length indicator for dnslabel available");
        }

        byte[] dnslabelBytes = new byte[len];
        if (is.read(dnslabelBytes) != dnslabelBytes.length) {
            throw new IOException("insufficient bytes available to read requested dnslabel");
        }

        return new String(dnslabelBytes, Charset.forName("ASCII"));
    }

    public static void writeDNSLabel(OutputStream os, String dnslabel) throws IOException {
        byte[] dnslabelBytes = dnslabel.toString().getBytes(Charset.forName("ASCII"));

        if (dnslabelBytes.length > 63) {
            throw new IOException("dnslabel too long to encode");
        }

        os.write(dnslabelBytes.length);
        os.write(dnslabelBytes);
    }

}
