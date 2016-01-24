package de.dogcraft.ssltest.dns.encoding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Packet {

    private final Header header = new Header();

    private final Section questions = new Section(false);

    private final Section answers = new Section(true);

    private final Section authority = new Section(true);

    private final Section additional = new Section(true);

    public Header getHeader() {
        return header;
    }

    public Section getQuestions() {
        return questions;
    }

    public Section getAnswers() {
        return answers;
    }

    public Section getAuthority() {
        return authority;
    }

    public Section getAdditional() {
        return additional;
    }

    public byte[] encode() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);

        encodeTo(baos);

        return baos.toByteArray();
    }

    public void encodeTo(OutputStream os) throws IOException {
        getHeader().encodeTo(os);
        getQuestions().encodeTo(os);
        getAnswers().encodeTo(os);
        getAuthority().encodeTo(os);
        getAdditional().encodeTo(os);
    }

}
