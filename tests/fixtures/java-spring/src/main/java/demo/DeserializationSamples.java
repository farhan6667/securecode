package demo;

// Test fixture for semgrep/java-spring.yml. Never compiled or run.
// A line "// expect: <rule>" means the rule must report the next line; nothing else may be reported.

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class DeserializationSamples {

    public Object readBad(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        // expect: java-unsafe-deserialization-objectinputstream
        return in.readObject();
    }

    public Object readFiltered(InputStream body) throws Exception {
        ObjectInputStream in = new ObjectInputStream(body);
        in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("demo.Safe;!*"));
        return in.readObject();
    }

    public Object xstreamBad(String xml) {
        XStream xs = new XStream();
        // expect: java-xstream-without-allowlist
        return xs.fromXML(xml);
    }

    public Object xstreamGood(String xml) {
        XStream xs = new XStream();
        xs.addPermission(NoTypePermission.NONE);
        xs.allowTypes(new Class[] { SafeDto.class });
        return xs.fromXML(xml);
    }

    public ObjectMapper jacksonBad() {
        ObjectMapper m = new ObjectMapper();
        // expect: java-jackson-default-typing
        m.enableDefaultTyping();
        return m;
    }

    public ObjectMapper jacksonBad2() {
        ObjectMapper m = new ObjectMapper();
        // expect: java-jackson-default-typing
        m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        return m;
    }

    public ObjectMapper jacksonGood() {
        ObjectMapper m = new ObjectMapper();
        m.findAndRegisterModules();
        return m;
    }

    static class Envelope {
        // expect: java-jackson-default-typing
        @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, property = "@class")
        public Object payload;

        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
        public Object typedPayload;
    }

    static class SafeDto { }
}
