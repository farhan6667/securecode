package demo;

// Test fixture for semgrep/java-spring.yml. Never compiled or run.

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

public class XmlSamples {

    public DocumentBuilder domBad() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // expect: java-xxe-documentbuilderfactory
        return dbf.newDocumentBuilder();
    }

    public DocumentBuilder domGood() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        return dbf.newDocumentBuilder();
    }

    public SAXParser saxBad() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        // expect: java-xxe-saxparserfactory
        return spf.newSAXParser();
    }

    public SAXParser saxGood() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return spf.newSAXParser();
    }

    public XMLStreamReader staxBad(InputStream in) throws Exception {
        XMLInputFactory f = XMLInputFactory.newInstance();
        // expect: java-xxe-xmlinputfactory
        return f.createXMLStreamReader(in);
    }

    public XMLStreamReader staxGood(InputStream in) throws Exception {
        XMLInputFactory f = XMLInputFactory.newInstance();
        f.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return f.createXMLStreamReader(in);
    }
}
