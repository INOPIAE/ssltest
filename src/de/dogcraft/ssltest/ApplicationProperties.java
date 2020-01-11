package de.dogcraft.ssltest;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class ApplicationProperties {

    private String applicationName = "SSL-Test";

    private String logo = "";

    private String navbarStyle = "navbar-inverse";

    private int port = 8080;

    public ApplicationProperties() throws FileNotFoundException, IOException {
        Properties prop = new Properties();
        prop.load(new FileInputStream("config/application.properties"));
        applicationName = prop.getProperty("applicationame");
        port = Integer.parseInt(prop.getProperty("port"));
        logo = prop.getProperty("logo");
        navbarStyle = prop.getProperty("navbarStyle");
    }

    public String getApplicationName() {
        return applicationName;
    }

    public int getPort() {
        return port;
    }

    public String getLogo() {
        return logo;
    }

    public String getNavbarStyle() {
        return navbarStyle;
    }
}
