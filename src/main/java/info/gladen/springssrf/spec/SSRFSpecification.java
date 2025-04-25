package info.gladen.springssrf.spec;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.*;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class SSRFSpecification implements FluentTQLUserInterface {
    public Method intraSrcMethod = new MethodConfigurator(
            "info.gladen.springssrf.SpringssrfApplication: " +
                    "org.springframework.http.ResponseEntity handleIntraVulnerability(" +
                    "java.lang.String)")
            .out().param(0)
            .configure();

    public Method interSrcMethod = new MethodConfigurator(
            "info.gladen.springssrf.SpringssrfApplication: " +
                    "org.springframework.http.ResponseEntity handleInterVulnerability(" +
                    "java.lang.String)")
            .out().param(0)
            .configure();

    public Method imageSrcMethod = new MethodConfigurator(
            "info.gladen.springssrf.SpringssrfApplication: " +
                    "org.springframework.http.ResponseEntity handleImageVulnerability(" +
                    "java.lang.String)")
            .out().param(0)
            .configure();

    public MethodSet sources = new MethodSet("sources")
            .addMethod(intraSrcMethod)
            .addMethod(interSrcMethod)
            .addMethod(imageSrcMethod);

    public Method requestBuilderSinkMethod = new MethodConfigurator(
            "java.net.http.HttpRequest$Builder: " +
                    "java.net.http.HttpRequest$Builder uri(" +
                    "java.net.URI)")
            .in().param(0)
            .configure();

    public Method imgSinkMethod = new MethodConfigurator(
            "javax.imageio.ImageIO: " +
                    "java.awt.image.BufferedImage read(" +
                    "java.net.URL)")
            .in().param(0)
            .configure();

    public MethodSet sinks = new MethodSet("sinks")
            .addMethod(requestBuilderSinkMethod)
            .addMethod(imgSinkMethod);

    public Method uriPropagator = new MethodConfigurator(
            "java.net.URI: " +
            "void <init>(" +
            "java.lang.String)")
            .in().param(0)
            .out().thisObject()
            .configure();

    public Method uriPropagatorStatic = new MethodConfigurator(
            "java.net.URI: " +
                    "java.net.URI create(" +
                    "java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method urlPropagator = new MethodConfigurator(
            "java.net.URI: " +
                    "java.net.URL toURL()")
            .in().thisObject()
            .out().returnValue()
            .configure();

    public Method urlPropagatorStatic = new MethodConfigurator(
            "java.net.URL: " +
                    "java.net.URL fromURI(" +
                    "java.net.URI)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public MethodSet propagators = new MethodSet("propagators")
            .addMethod(uriPropagator)
            .addMethod(uriPropagatorStatic)
            .addMethod(urlPropagator)
            .addMethod(urlPropagatorStatic);

    public Method sanitizer = new MethodConfigurator("info.gladen.springssrf.SSRFSanitizers: " +
            "java.lang.String sanitize(" +
            "java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("SSRF")
                .from(sources)
                .through(propagators)
                .notThrough(sanitizer)
                .to(sinks)
                .report("Found a SSRF vulnerability", CWE.CWE20) // CWE918 for SSRF, but not implemented, yet.
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}
