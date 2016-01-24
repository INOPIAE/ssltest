package de.dogcraft.ssltest.dns.encoding;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Header {

    private short id;

    private boolean isResponse;

    private Opcode opcode;

    private boolean isAuthoritative;

    private boolean isTruncated;

    private boolean isRecursionDesired;

    private boolean isRecursionAvailable;

    private boolean reserved;

    private ResponseCode rcode;

    private int questionCount;

    private int answersCount;

    private int authorityCount;

    private int additionalCount;

    public short getId() {
        return id;
    }

    public void setId(short id) {
        this.id = id;
    }

    public boolean isResponse() {
        return isResponse;
    }

    public void setResponse(boolean isResponse) {
        this.isResponse = isResponse;
    }

    public Opcode getOpcode() {
        return opcode;
    }

    public void setOpcode(Opcode opcode) {
        this.opcode = opcode;
    }

    public boolean isAuthoritative() {
        return isAuthoritative;
    }

    public void setAuthoritative(boolean isAuthoritative) {
        this.isAuthoritative = isAuthoritative;
    }

    public boolean isTruncated() {
        return isTruncated;
    }

    public void setTruncated(boolean isTruncated) {
        this.isTruncated = isTruncated;
    }

    public boolean isRecursionDesired() {
        return isRecursionDesired;
    }

    public void setRecursionDesired(boolean isRecursionDesired) {
        this.isRecursionDesired = isRecursionDesired;
    }

    public boolean isRecursionAvailable() {
        return isRecursionAvailable;
    }

    public void setRecursionAvailable(boolean isRecursionAvailable) {
        this.isRecursionAvailable = isRecursionAvailable;
    }

    public boolean isReserved() {
        return reserved;
    }

    public void setReserved(boolean reserved) {
        this.reserved = reserved;
    }

    public ResponseCode getRcode() {
        return rcode;
    }

    public void setRcode(ResponseCode rcode) {
        this.rcode = rcode;
    }

    public int getQuestionCount() {
        return questionCount;
    }

    public void setQuestionCount(int questionCount) {
        this.questionCount = questionCount;
    }

    public int getAnswersCount() {
        return answersCount;
    }

    public void setAnswersCount(int answersCount) {
        this.answersCount = answersCount;
    }

    public int getAuthorityCount() {
        return authorityCount;
    }

    public void setAuthorityCount(int authorityCount) {
        this.authorityCount = authorityCount;
    }

    public int getAdditionalCount() {
        return additionalCount;
    }

    public void setAdditionalCount(int additionalCount) {
        this.additionalCount = additionalCount;
    }

    public void encodeTo(OutputStream os) throws IOException {
        DataOutputStream dos = new DataOutputStream(os);

        dos.writeShort(id);

        short foo = 0;
        if (isResponse()) {
            foo |= 1 << 15;
        }

        foo |= (getOpcode().id & 0xF) << 11;
        if (isAuthoritative()) {
            foo |= 1 << 10;
        }
        if (isTruncated()) {
            foo |= 1 << 9;
        }
        if (isRecursionDesired()) {
            foo |= 1 << 8;
        }
        if (isRecursionAvailable()) {
            foo |= 1 << 7;
        }

        foo |= getRcode().id & 0xF;

        dos.writeShort(foo);

        dos.writeShort(getQuestionCount());
        dos.writeShort(getAnswersCount());
        dos.writeShort(getAuthorityCount());
        dos.writeShort(getAdditionalCount());
    }

}
