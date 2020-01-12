package de.dogcraft.ssltest.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.crypto.interfaces.DHPublicKey;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import de.dogcraft.ssltest.utils.Truststore;
import de.dogcraft.ssltest.utils.TruststoreGroup;
import de.dogcraft.ssltest.utils.TruststoreUtil;
import sun.security.x509.AVA;
import sun.security.x509.X500Name;

public class TruststoreOverview extends HttpServlet {

    private static final long serialVersionUID = 1L;

    class CertificateIdentifier implements Comparable<CertificateIdentifier> {

        String hash;

        String o;

        String ou;

        String cn;

        String other;

        int count;

        String pubkey;

        String country;

        private X509Certificate c;

        public CertificateIdentifier(X509Certificate c, int count) {
            this.count = count;
            this.c = c;
            try {
                pubkey = TruststoreUtil.outputFingerprint(c.getPublicKey().getEncoded(), MessageDigest.getInstance("SHA-512"));
                hash = c.getSigAlgName();
                if ("1.3.36.3.3.1.2".equals(hash)) {
                    hash = "RIPEMD160withRSA";
                }
                X500Name n = new X500Name(c.getSubjectX500Principal().getEncoded());
                o = n.getOrganization();
                ou = n.getOrganizationalUnit();
                try {
                    cn = n.getCommonName();
                } catch (IOException e) {
                    System.out.println(String.format("Error in cn of %s O=%s OU=%s", pubkey, o, ou));
                }
                country = n.getCountry();
                other = "";
                for (AVA i : n.allAvas()) {
                    if (i.getObjectIdentifier() == X500Name.commonName_oid)
                        continue;
                    if (i.getObjectIdentifier() == X500Name.orgName_oid)
                        continue;
                    if (i.getObjectIdentifier() == X500Name.orgUnitName_oid)
                        continue;
                    if (i.getObjectIdentifier() == X500Name.countryName_oid)
                        continue;
                    if (other.length() != 0) {
                        other += ", ";
                    }
                    other += i.toRFC1779String();
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }

        public void print(PrintWriter pw, String print) {
            pw.print("<th>");
            output(pw, country);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, o);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, ou);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, cn);
            pw.print("</th>");
            pw.print("<th>");
            output(pw, other);
            pw.print("</th>");
            pw.print("<th class=\"" + hash + "\">");
            pw.print(hash);
            pw.print("</th>");
            PublicKey pk = c.getPublicKey();
            if (pk instanceof RSAPublicKey) {
                pw.print("<th style=\"background-color:#CCFFCC;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                int bitLength = ((RSAPublicKey) pk).getModulus().bitLength();
                String bitsec;
                if (bitLength <= 512) {
                    bitsec = "background-color: #FF4444;";
                } else if (bitLength < 1024) {
                    bitsec = "background-color: #FF8888;";
                } else if (bitLength < 2048) {
                    bitsec = "background-color: #FFCCCC;";
                } else if (bitLength < 3072) {
                    bitsec = "background-color: #FFDDCC;";
                } else if (bitLength < 4096) {
                    bitsec = "background-color: #FFEECC;";
                } else if (bitLength < 6144) {
                    bitsec = "background-color: #FFFFCC;";
                } else if (bitLength < 8192) {
                    bitsec = "background-color: #EEFFCC;";
                } else if (bitLength < 12288) {
                    bitsec = "background-color: #DDFFCC;";
                } else if (bitLength < 16384) {
                    bitsec = "background-color: #CCFFCC;";
                } else if (bitLength < 32768) {
                    bitsec = "background-color: #CCFFFF;";
                } else if (bitLength < 65536) {
                    bitsec = "background-color: #CCCCFF;";
                } else {
                    bitsec = "background-color: #8888FF;";
                }
                pw.print("<th style=\"" + bitsec + "\">");
                pw.print(bitLength);
                pw.print("</th>");
                pw.print("<th>");
                BigInteger publicExponent = ((RSAPublicKey) pk).getPublicExponent();
                if (publicExponent.bitLength() > 50) {
                    pw.print("e = [" + publicExponent.bitLength() + "bit]");
                } else {
                    pw.print("e = " + publicExponent);
                }
                pw.print("</th>");
            } else if (pk instanceof ECPublicKey) {
                pw.print("<th style=\"background-color:#CCCCFF;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                EllipticCurve ec = ((ECPublicKey) pk).getParams().getCurve();
                int bitLength = ec.getField().getFieldSize();
                String bitsec;
                if (bitLength <= 192) {
                    bitsec = "background-color: #FF4444;";
                } else if (bitLength < 224) {
                    bitsec = "background-color: #FF8888;";
                } else if (bitLength < 256) {
                    bitsec = "background-color: #FFCCCC;";
                } else if (bitLength < 320) {
                    bitsec = "background-color: #FFDDCC;";
                } else if (bitLength < 384) {
                    bitsec = "background-color: #FFEECC;";
                } else if (bitLength < 416) {
                    bitsec = "background-color: #FFFFCC;";
                } else if (bitLength < 448) {
                    bitsec = "background-color: #EEFFCC;";
                } else if (bitLength < 480) {
                    bitsec = "background-color: #DDFFCC;";
                } else if (bitLength < 512) {
                    bitsec = "background-color: #CCFFCC;";
                } else if (bitLength < 640) {
                    bitsec = "background-color: #CCFFFF;";
                } else if (bitLength < 768) {
                    bitsec = "background-color: #CCCCFF;";
                } else {
                    bitsec = "background-color: #8888FF;";
                }
                pw.print("<th style=\"" + bitsec + "\">");
                pw.print(bitLength);
                pw.print("</th>");
                pw.print("<th>");
                pw.print("Char = ?, Curve = ?");
                pw.print("</th>");
            } else if (pk instanceof DSAPublicKey) {
                pw.print("<th style=\"background-color:#FFCCCC;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                int bitLength = ((DSAPublicKey) pk).getY().bitLength();
                String bitsec;
                if (bitLength <= 512) {
                    bitsec = "background-color: #FF4444;";
                } else if (bitLength < 1024) {
                    bitsec = "background-color: #FF8888;";
                } else if (bitLength < 2048) {
                    bitsec = "background-color: #FFCCCC;";
                } else if (bitLength < 3072) {
                    bitsec = "background-color: #FFDDCC;";
                } else if (bitLength < 4096) {
                    bitsec = "background-color: #FFEECC;";
                } else if (bitLength < 6144) {
                    bitsec = "background-color: #FFFFCC;";
                } else if (bitLength < 8192) {
                    bitsec = "background-color: #EEFFCC;";
                } else if (bitLength < 12288) {
                    bitsec = "background-color: #DDFFCC;";
                } else if (bitLength < 16384) {
                    bitsec = "background-color: #CCFFCC;";
                } else if (bitLength < 32768) {
                    bitsec = "background-color: #CCFFFF;";
                } else if (bitLength < 65536) {
                    bitsec = "background-color: #CCCCFF;";
                } else {
                    bitsec = "background-color: #8888FF;";
                }
                pw.print("<th style=\"" + bitsec + "\">");
                pw.print(bitLength);
                pw.print("</th>");
                pw.print("<th>");
                pw.print("g = ?, y = ?");
                pw.print("</th>");
            } else if (pk instanceof DHPublicKey) {
                pw.print("<th style=\"background-color:#FFFFCC;\">");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                pw.print("<th>");
                pw.print(((DHPublicKey) pk).getY().bitLength());
                pw.print("</th>");
                pw.print("<th>");
                pw.print("g = ?");
                pw.print("</th>");
            } else {
                pw.print("<th>");
                pw.print(pk.getAlgorithm());
                pw.print("</th>");
                pw.print("<th>");
                pw.print("-");
                pw.print("</th>");
                pw.print("<th>");
                pw.print("-");
                pw.print("</th>");
            }
            pw.print("<th style='text-align: left' title='" + print + "'>");
            pw.print(pubkey.substring(pubkey.length() - 8));
            pw.print("</th>");
            pw.print("<th>");
            if (count != 1) {
                pw.print(count);
            } else {
                pw.print("&nbsp;");
            }
            pw.print("</th>");

        }

        private void output(PrintWriter pw, String data) {
            if (data != null)
                pw.print(data);
        }

        @Override
        public int compareTo(CertificateIdentifier target) {
            if (target == null)
                return -1;
            int i = compare(o, target.o);
            if (i != 0)
                return i;
            i = compare(ou, target.ou);
            if (i != 0)
                return i;
            i = compare(cn, target.cn);
            if (i != 0)
                return i;
            i = compare(other, target.other);
            if (i != 0)
                return i;
            return Integer.compare(count, target.count);
        }

        private int compare(String a, String b) {
            if (a == null && b == null)
                return 0;
            if (a == null)
                return -1;
            if (b == null) {
                return 1;

            }
            return a.compareTo(b);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        this.doGet(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html; charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        resp.addHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self';");

        String root = req.getParameter("root") == null ? "" : req.getParameter("root").toLowerCase();

        PrintWriter pw = resp.getWriter();

        BufferedReader br = new BufferedReader(new InputStreamReader(Service.replaceHTML(Service.class.getResourceAsStream("../res/header.htm"), "trust"), "UTF-8"));
        String line;
        while ((line = br.readLine()) != null) {
            pw.println(line);
        }
        try {
            Truststore any = TruststoreGroup.getAnyTruststore();
            KeyStore ks = any.getKeyStore();
            pw.print("<div class=\"container\" id=\"container\" role=\"main\">");
            pw.print("<div class=\"jumbotron\">");
            pw.print("<h1>Trust</h1>");
            pw.print(String.format("<p>Find a root or intermediate certificate out of %s certificates in the database.</p>", ks.size()));

            pw.print("<form method=\"POST\" id=\"reqform\">");
            pw.print("<div class=\"input-group space-below\">");
            pw.print("<span class=\"input-group-addon\">Subject (CN)</span>");
            pw.print("<input type=\"text\" class=\"form-control\" name=\"root\" id=\"root\" placeholder=\"enter part of the subject entry or * for all\" />");
            pw.print("</div>");
            pw.print("<input type=\"submit\" value=\"Find\" class=\"btn btn-primary btn-lg\">");
            pw.print("</form>");

            switch (root) {
            case "*":
                pw.print("<p>List of all known root certificate</p>");
                break;
            case "":
                pw.print("<p>Add an entry to the filter</p>");
                break;
            default:
                pw.print(String.format("<p>List of all known root certificate containing '%s' in the subject</p>", root));
                break;
            }

            pw.print("</div>");
            pw.print("</div>");

            Enumeration<String> al = ks.aliases();
            TreeMap<CertificateIdentifier, Certificate> certs = new TreeMap<>();
            while (al.hasMoreElements()) {
                String alias = al.nextElement();
                X509Certificate c;
                CertificateIdentifier gname;
                try {
                    c = (X509Certificate) ks.getCertificate(alias);
                    gname = new CertificateIdentifier(c, 1);
                } catch (Exception e) {
                    System.err.println("Error in " + alias + " of class " + e.getClass().getName() + ": " + e.getMessage());
                    continue;
                }
                int i = 2;
                while (certs.containsKey(gname)) {
                    gname.count = i++;
                }
                certs.put(gname, c);
            }
            if ( !root.isEmpty()) {
                pw.println("<table border='1'>");
                pw.print("<tr><th>C</th><th>O</th><th>OU</th><th>CN</th><th>other dn</th><th>signature</th><th>keyType</th><th>keySize</th><th>keyDetail</th><th>pubkey ID</th><th>#</th><th>from</th><th>to</th><th><span title='selfsigned'>S</span>");
                for (Entry<String, TruststoreGroup> truststore : TruststoreGroup.getStores().entrySet()) {
                    for (Entry<String, Truststore> entry : truststore.getValue().getContainedTables().entrySet()) {
                        pw.print("<th class='rotate'><div><span title='");
                        pw.print(truststore.getKey() + "/" + entry.getKey());
                        pw.print("'>");
                        pw.print(truststore.getKey() + "/" + entry.getKey());
                        pw.print("</span></div></th>");
                    }
                }
                pw.println("</tr>");
                for (Entry<CertificateIdentifier, Certificate> e : certs.entrySet()) {
                    X509Certificate cert = (X509Certificate) e.getValue();
                    if (cert.getSubjectDN().toString().toLowerCase().contains(root) || root.equals("*")) {
                        pw.print("<tr>");
                        e.getKey().print(pw, TruststoreUtil.outputFingerprint(e.getValue(), MessageDigest.getInstance("SHA-512")));
                        outputDate(pw, cert.getNotBefore(), false);
                        outputDate(pw, cert.getNotAfter(), true);
                        pw.print("<td>");
                        try {
                            cert.verify(cert.getPublicKey());
                            pw.print("S");
                        } catch (InvalidKeyException ex) {
                            pw.print("U");
                        } catch (NoSuchAlgorithmException ex) {
                            pw.print("A");
                        } catch (SignatureException ex) {
                        }
                        pw.print("</td>");
                        for (Entry<String, TruststoreGroup> truststore : TruststoreGroup.getStores().entrySet()) {
                            for (Entry<String, Truststore> ttab : truststore.getValue().getContainedTables().entrySet()) {
                                pw.print("<td class='" + truststore.getKey() + "'>");
                                pw.print("<span title='" + truststore.getKey() + "/" + ttab.getKey() + "' style='color: ");
                                // float val =
                                // truststore.getValue().contains(e.getValue());
                                if (ttab.getValue().contains(e.getValue())) {
                                    pw.print("green'>&#x2714;</span>");// check:
                                                                       //
                                } else {
                                    pw.print("red'>&#x2718;</span>"); // cross:
                                                                      //
                                }
                                pw.print("</td>");
                            }
                        }
                        pw.println("</tr>");
                    }
                }
                pw.println("</table>");
            }
            br = new BufferedReader(new InputStreamReader(Service.replaceHTML(Service.class.getResourceAsStream("../res/footer.htm"), ""), "UTF-8"));
            while ((line = br.readLine()) != null) {
                pw.println(line);
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

    private void outputDate(PrintWriter pw, Date notBefore, boolean endOfLife) {
        String attrib = " style=\"";

        Date now = new Date();
        Long diff = notBefore.getTime() - now.getTime();

        if ( !endOfLife) {
            diff = -diff;
        }

        if (diff < 0) {
            attrib += "background-color: #FF8888;";
        } else {
            diff /= 1000;
            diff /= 86400;
            diff /= 30;

            if (diff < 3) {
                attrib += "background-color: #FFCCCC;";
            } else if (diff < 6) {
                attrib += "background-color: #FFDDCC;";
            } else if (diff < 12) {
                attrib += "background-color: #FFEECC;";
            } else if (diff < 24) {
                attrib += "background-color: #FFFFCC;";
            } else if (diff < 36) {
                attrib += "background-color: #EEFFCC;";
            } else if (diff < 60) {
                attrib += "background-color: #DDFFCC;";
            } else if (diff < 120) {
                attrib += "background-color: #CCFFCC;";
            } else if (diff < 140) {
                attrib += "background-color: #CCFFDD;";
            } else if (diff < 160) {
                attrib += "background-color: #CCFFEE;";
            } else if (diff < 180) {
                attrib += "background-color: #CCFFFF;";
            } else if (diff < 200) {
                attrib += "background-color: #CCEEFF;";
            } else if (diff < 220) {
                attrib += "background-color: #CCDDFF;";
            } else if (diff < 240) {
                attrib += "background-color: #CCCCFF;";
            } else if (diff < 260) {
                attrib += "background-color: #B0CCFF;";
            } else if (diff < 280) {
                attrib += "background-color: #9CCCFF;";
            } else if (diff < 300) {
                attrib += "background-color: #8888FF;";
            } else {
                attrib += "background-color: #FF88FF;";
            }
        }

        attrib += "\"";
        outputDate(pw, notBefore, attrib);
    }

    private void outputDate(PrintWriter pw, Date notBefore, String attrib) {
        Calendar gc = Calendar.getInstance();
        gc.setTime(notBefore);
        pw.print("<td title=\"" + notBefore + "\"" + attrib + ">" + gc.get(Calendar.YEAR) + "</td>");
    }
}
