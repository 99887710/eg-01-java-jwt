package com.docusign.example.jwt;

import com.docusign.esign.client.ApiClient;
import com.docusign.esign.client.ApiException;
import com.docusign.esign.model.Envelope;
import com.docusign.esign.model.EnvelopeSummary;
import com.docusign.esign.model.EnvelopesInformation;
import com.docusign.esign.model.Recipients;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.docusign.example.jwt.DSHelper.printPrettyJSON;

public class JWTExample {

    private static final ApiClient apiClient = new ApiClient();

    public static void main(String args[]) {
        try {
            System.setProperty("https.protocols","TLSv1.2");
            System.out.println("\nSending an envelope. The envelope includes HTML, Word, and PDF documents. It takes about 15 seconds for DocuSign to process the envelope request... ");
            EnvelopeSummary result = new SendEnvelope(apiClient).sendEnvelope();
            System.out.println(
                    String.format("Envelope status: %s. Envelope ID: %s",
                    result.getStatus(),
                    result.getEnvelopeId()));

            System.out.println("\nListing envelopes in the account...");
            EnvelopesInformation envelopesList = new ListEnvelopes(apiClient).list();

            List<Envelope> envelopes = envelopesList.getEnvelopes();
            if(envelopesList != null && envelopes.size() > 2) {
                System.out.println(
                        String.format("Results for %d envelopes were returned. Showing the first two:",
                                envelopesList.getEnvelopes().size()));
                                envelopesList.setEnvelopes(Arrays.asList(envelopes.get(0), envelopes.get(1)));
            }

            printPrettyJSON(envelopesList);

            System.out.println("Done. Hit enter to exit the example");
            System.in.read();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ApiException e) {
            System.err.println("\nDocuSign Exception!");

            // Special handling for consent_required
            String message = e.getMessage();
            if(message != null && message.contains("consent_required")){
                String consent_url = String.format("%s/oauth/auth?response_type=code&scope=%s" +
                        "&client_id=%s" +
                        "&redirect_uri=%s",
                        DSConfig.DS_AUTH_SERVER,
                        DSConfig.PERMISSION_SCOPES,
                        DSConfig.CLIENT_ID,
                        DSConfig.OAUTH_REDIRECT_URI);
                System.err.println("\nC O N S E N T   R E Q U I R E D" +
                        "\nAsk the user who will be impersonated to run the following url: " +
                        "\n"+ consent_url+
                        "\n\nIt will ask the user to login and to approve access by your application." +
                        "\nAlternatively, an Administrator can use Organization Administration to" +
                        "\npre-approve one or more users.");
            } else {
                e.printStackTrace();
                System.err.println(String.format("    Reason1: %s", message));
                System.err.println(String.format("    Reason: %d", e.getCode()));
                System.err.println(String.format("    Error Reponse: %s", e.getResponseBody()));
            }
        }
    }
}
