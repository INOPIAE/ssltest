package de.dogcraft.ssltest.service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import de.dogcraft.ssltest.KnownDHGroup;
import de.dogcraft.ssltest.Standalone;
import de.dogcraft.ssltest.utils.CertificateWrapper;
import de.dogcraft.ssltest.utils.IOUtils;
import de.dogcraft.ssltest.utils.PEM;
import de.dogcraft.ssltest.utils.ReplacingInputStream;
import de.dogcraft.ssltest.utils.TruststoreGroup;

public class Service extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final MultipartConfigElement MULTI_PART_CONFIG = new MultipartConfigElement(System.getProperty("java.io.tmpdir"), 1024 * 1024, 1024 * 1024, 1024 * 1024);

    @Override
    public void init() throws ServletException {
        TruststoreGroup.getAnyTruststore();
        System.out.println("Truststore Inited");
        KnownDHGroup.lookup(null);
        System.out.println("DH Params Inited");
        System.out.println(CertificateTestService.getCAs().size() + " CAs loaded");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }

    private static void copyStream(InputStream in, OutputStream out) {
        try {
            try {
                try {
                    int len;
                    byte[] buf = new byte[65536];

                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                } finally {
                    out.close();
                }
            } finally {
                in.close();
            }
        } catch (IOException e) {
        }
    }

    private static void copyStream(InputStream inHeader, InputStream in, InputStream inFooter, OutputStream out) {
        try {
            try {
                try {
                    int len;
                    byte[] buf = new byte[65536];

                    while ((len = inHeader.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                    while ((len = inFooter.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                } finally {
                    out.close();
                }
            } finally {
                in.close();
                inHeader.close();
            }
        } catch (IOException e) {
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setCharacterEncoding("UTF-8");
        resp.addHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; font-src 'self';");

        String path = req.getPathInfo();
        if (path == null || path.equals("/")) {
            resp.setContentType("text/html");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(replaceHTML(Service.class.getResourceAsStream("../res/header.htm"), "server"), Service.class.getResourceAsStream("../res/index.htm"), replaceHTML(Service.class.getResourceAsStream("../res/footer.htm"), ""), resp.getOutputStream());
        } else if (path.equals("/about")) {
            resp.setContentType("text/html");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(replaceHTML(Service.class.getResourceAsStream("../res/header.htm"), "about"), Service.class.getResourceAsStream("../res/about.htm"), replaceHTML(Service.class.getResourceAsStream("../res/footer.htm"), ""), resp.getOutputStream());
        } else if (path.equals("/dataprotection")) {
            resp.setContentType("text/html");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(replaceHTML(Service.class.getResourceAsStream("../res/header.htm"), ""), Service.class.getResourceAsStream("../res/dataprotection.htm"), replaceHTML(Service.class.getResourceAsStream("../res/footer.htm"), "dataprotection"), resp.getOutputStream());
        } else if (path.equals("/imprint")) {
            resp.setContentType("text/html");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(replaceHTML(Service.class.getResourceAsStream("../res/header.htm"), ""), Service.class.getResourceAsStream("../res/imprint.htm"), replaceHTML(Service.class.getResourceAsStream("../res/footer.htm"), "imprint"), resp.getOutputStream());
        } else if (path.equals("/cert")) {
            resp.setContentType("text/html");
            resp.setDateHeader("Last-Modified", ManagementFactory.getRuntimeMXBean().getStartTime());
            copyStream(replaceHTML(Service.class.getResourceAsStream("../res/header.htm"), "cert"), Service.class.getResourceAsStream("../res/cert.htm"), replaceHTML(Service.class.getResourceAsStream("../res/footer.htm"), ""), resp.getOutputStream());
        } else if (path.equals("/server.event")) {
            resp.addHeader("Cache-Control", "max-age=0");
            if (req.getParameter("domain") != null) {
                reqTestServer(req, resp, true);
            }
        } else if (path.equals("/server.txt")) {
            resp.addHeader("Cache-Control", "max-age=0");
            if (req.getParameter("domain") != null) {
                reqTestServer(req, resp, false);
            }
        } else if (path.equals("/serverclear")) {
            ServerTestService.clearCache();
            resp.sendRedirect("/");
        } else if (path.equals("/cert.event")) {
            resp.addHeader("Cache-Control", "max-age=0");
            if (req.getParameter("fp") != null) {
                reqTestCertificate(req, resp, true);
            }
        } else if (path.equals("/cert.txt")) {
            resp.addHeader("Cache-Control", "max-age=0");
            if (req.getParameter("fp") != null) {
                reqTestCertificate(req, resp, false);
            }
        } else if (path.equals("/certclear")) {
            CertificateTestService.clearCache();
            resp.sendRedirect("/cert");
        } else if (path.equals("/oid.js")) {
            OIDs.outputOids(resp);
        } else if (path.equals("/certstatus")) {
            if (req.getMethod().equals("POST") && req.getContentType().startsWith("multipart/form-data")) {
                req.setAttribute(Request.__MULTIPART_CONFIG_ELEMENT, MULTI_PART_CONFIG);
                InputStream in = req.getPart("file").getInputStream();
                CertificateWrapper cw = insertCert(in);
                if (cw == null) {
                    resp.sendError(500, "Certificate issuer not found");
                    return;
                }
                CertificateTestService.cache(cw);
                resp.sendRedirect("/cert.txt?fp=" + cw.getHash());
            } else if (req.getMethod().equals("POST")) {
                CertificateWrapper cw = insertCert(req.getInputStream());
                if (cw == null) {
                    resp.sendError(500, "Certificate issuer not found");
                    return;
                }
                CertificateTestService.cache(cw);
                resp.setHeader("Content-type", "text/plain;charset=UTF-8");
                resp.addHeader("Cache-Control", "max-age=0");
                resp.getWriter().print(cw.getHash());
            } else {
                resp.setHeader("Content-type", "text/html;charset=UTF-8");
                resp.addHeader("Cache-Control", "max-age=86400");
                ServletOutputStream out = resp.getOutputStream();
                out.println("<form method='POST' enctype='multipart/form-data'><input type='file' name='file'><input type='submit'></form>");
            }
        } else if (path.equals("/cipherRater.css")) {
            resp.addHeader("Cache-Control", "max-age=86400");
            CipherRater.generateRateCSS(resp);
        } else {
            resp.addHeader("Cache-Control", "max-age=86400");
            resp.sendError(404, "Fuck off");
        }
    }

    private CertificateWrapper insertCert(InputStream in) throws IOException, ServletException, UnsupportedEncodingException {
        byte[] data = IOUtils.get(in);
        if (data.length > 4 && data[0] == '-' && data[1] == '-' && data[2] == '-' && data[3] == '-' && data[4] == '-') {
            data = PEM.decode("CERTIFICATE", new String(data, "UTF-8"));
        }
        org.bouncycastle.asn1.x509.Certificate c1 = org.bouncycastle.asn1.x509.Certificate.getInstance(data);

        CertificateWrapper cw = toCw(c1);
        return cw;
    }

    private CertificateWrapper toCw(org.bouncycastle.asn1.x509.Certificate c1) {
        for (CertificateWrapper s : CertificateTestService.getCAs()) {
            if (s.getC().getSubject().equals(c1.getIssuer())) {
                return new CertificateWrapper(c1, s);
            }
        }
        return null;
    }

    private void reqTestServer(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        ServerTestService sts = new ServerTestService();
        sts.performTest(req, resp, useEventStream);
    }

    private void reqTestCertificate(HttpServletRequest req, HttpServletResponse resp, boolean useEventStream) throws IOException {
        CertificateTestService cts = new CertificateTestService();
        cts.performTest(req, resp, useEventStream);
    }

    public static InputStream replaceHTML(InputStream in, String page) throws FileNotFoundException, IOException {
        in = new ReplacingInputStream(in, "$application", Standalone.app.getApplicationName());
        in = new ReplacingInputStream(in, "$classserver", page.contains("server") ? "active" : "");
        in = new ReplacingInputStream(in, "$classcert", page.contains("cert") ? "active" : "");
        in = new ReplacingInputStream(in, "$classtrust", page.contains("trust") ? "active" : "");
        in = new ReplacingInputStream(in, "$classdataprotection", page.contains("dataprotection") ? "active" : "");
        in = new ReplacingInputStream(in, "$year", new SimpleDateFormat("yyyy").format(new Date()));
        in = new ReplacingInputStream(in, "$navbarstyle", Standalone.app.getNavbarStyle());
        in = new ReplacingInputStream(in, "$logo", Standalone.app.getLogo());
        if (Standalone.app.getImprint()) {
            in = new ReplacingInputStream(in, "$imprint", "<li  class=\"" + (page.contains("imprint") ? "active" : "") + "\"><a href=\"imprint\">Imprint</a></li>");
        }
        return new ReplacingInputStream(in, "$classabout", page.contains("about") ? "active" : "");
    }
}
