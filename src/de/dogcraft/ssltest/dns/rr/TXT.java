package de.dogcraft.ssltest.dns.rr;

import de.dogcraft.ssltest.dns.encoding.EntityContainer;
import de.dogcraft.ssltest.dns.encoding.NamedEntityContainer;
import de.dogcraft.ssltest.dns.encoding.blocks.Container;
import de.dogcraft.ssltest.dns.encoding.blocks.Text;

public class TXT extends RR {

    private String text;

    static {
        parserFormat.add(
                new NamedEntityContainer<Container>(
                        "TEXT",
                        new Container(
                                new EntityContainer<Text>(Text.class)
                        )
                )
                );    // TEXT
    }

    @Override
    public boolean isWellKnown() {
        return true;
    }

    @Override
    public String getTypeName() {
        return "TXT";
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

}
