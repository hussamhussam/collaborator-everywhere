package burp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.*;

public class BurpExtender implements IBurpExtender {
    private static final String name = "Interactsh Everywhere";
    private static final String version = "1.3";

    // provides potentially useful info but increases memory usage
    static final boolean SAVE_RESPONSES = false;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        new Utilities(callbacks);
        callbacks.setExtensionName(name);

        //Correlator collab = new Correlator();

        //Monitor collabMonitor = new Monitor(collab);
        //new Thread(collabMonitor).start();
        //callbacks.registerExtensionStateListener(collabMonitor);

        callbacks.registerProxyListener(new Injector());

        Utilities.out("Loaded " + name + " v" + version);
    }
}
class MetaRequest {
    private IHttpRequestResponse request;
    private int burpId;
    private long timestamp;

    MetaRequest(IInterceptedProxyMessage proxyMessage) {
        request = proxyMessage.getMessageInfo();
        burpId = proxyMessage.getMessageReference();
        timestamp = System.currentTimeMillis();
    }

    public void overwriteRequest(IHttpRequestResponse response) {
        request = response;
    }

    public IHttpRequestResponse getRequest() {
        return request;
    }

    public int getBurpId() {
        return burpId;
    }

    public long getTimestamp() {
        return timestamp;
    }
}

class Injector implements IProxyListener {

    private String collab = "425a2logssrf.22timer.ga";
    HashSet<String[]> injectionPoints = new HashSet<>();


    Injector() {
        //this.collab = collab;

        Scanner s = new Scanner(getClass().getResourceAsStream("/injections"));
        while (s.hasNextLine()) {
            String injection = s.nextLine();
            if (injection.charAt(0) == '#') {
                continue;
            }
            injectionPoints.add(injection.split(",", 3));
        }
        s.close();

    }

    public byte[] injectPayloads(String normurl,byte[] request){//, Integer requestCode) {

        //request = Utilities.replaceRequestLine(request, "GET @"+collabId + "/"+collabId.split("[.]")[0] + " HTTP/1.1");
        //request = Utilities.addOrReplaceHeader(request, "Referer", "http://portswigger-labs.net/redirect.php?url=https://portswigger-labs.net/"+collabId);

        request = Utilities.addOrReplaceHeader(request, "Cache-Control", "no-transform");

        for (String[] injection: injectionPoints) {
            String payload = injection[2].replace("%s", normurl+"."+collab);
	    // replace %h with corresponding Host header (same as with %s for Collaborator)
	    payload = payload.replace("%h", Utilities.getHeader(request, "Host"));
            switch ( injection[0] ){
                case "param":
                    IParameter param = Utilities.helpers.buildParameter(injection[1], payload, IParameter.PARAM_URL);
                    request = Utilities.helpers.removeParameter(request, param);
                    request = Utilities.helpers.addParameter(request, param);
                    break;

                case "header":
                    request = Utilities.addOrReplaceHeader(request, injection[1], payload);
                    break;
                default:
                    Utilities.out("Unrecognised injection type: " + injection[0]);
            }
            
        }

        return request;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxyMessage) {
        if (!messageIsRequest) {
            //if (BurpExtender.SAVE_RESPONSES) {
            //    collab.updateResponse(proxyMessage.getMessageReference(), proxyMessage.getMessageInfo());
            //}
            return;
        }

        IHttpRequestResponse messageInfo = proxyMessage.getMessageInfo();
	
	// only tamper with requests that are in scope
	IRequestInfo reqinfo = Utilities.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
	
	if (!Utilities.callbacks.isInScope(reqinfo.getUrl())) {
		return;
	}

        // don't tamper with requests already heading to the collaborator
        if (messageInfo.getHttpService().getHost().endsWith(collab)) {
            return;
        }

        //MetaRequest req = new MetaRequest(proxyMessage);
        //Integer requestCode = collab.addRequest(req);

        messageInfo.setRequest(injectPayloads(reqinfo.getUrl().toString().split("://")[1].split("\\?")[0].replaceAll("/$", "").replaceAll("/","-"),messageInfo.getRequest()));//, requestCode));


    }

}
