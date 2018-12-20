package com.docusign.example.jwt;

import com.docusign.esign.client.*;
import com.docusign.esign.client.auth.OAuth;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

/**
 * This is an example base class to be extended to show functionality example.
 * its has a apiClient member as a constructor argument for later usage in API calls.
 */
public class ExampleBase {

    private static final long TOKEN_EXPIRATION_IN_SECONDS = 3600;
    private static final long TOKEN_REPLACEMENT_IN_MILLISECONDS = 10 * 60 * 1000;

    private static OAuth.Account _account;
    private static File privateKeyTempFile = null;
    private static long expiresIn;
    private static String _token = null;
    protected final ApiClient apiClient;


    protected static String getAccountId() {
        return _account.getAccountId();
    };


    public ExampleBase(ApiClient apiClient) throws IOException {
        this.apiClient =  apiClient;
    }

    protected void checkToken() throws IOException, ApiException {
        if(this._token == null
                || (System.currentTimeMillis() + TOKEN_REPLACEMENT_IN_MILLISECONDS) > this.expiresIn) {
            updateToken();
        }
    }

    private void updateToken() throws IOException, ApiException {
        System.out.println("\nFetching an access token via JWT grant...");

        java.util.List<String> scopes = new ArrayList<String>();
        // Only signature scope is needed. Impersonation scope is implied.
        scopes.add(OAuth.Scope_SIGNATURE);
        String privateKey = DSConfig.PRIVATE_KEY.replace("\\n","\n");
        System.out.println(privateKey);
        byte[] privateKeyBytes = privateKey.getBytes();
        apiClient.setOAuthBasePath(DSConfig.DS_AUTH_SERVER);

        System.out.println(apiClient.getJWTUri(DSConfig.CLIENT_ID, "http://localhost:8080",DSConfig.DS_AUTH_SERVER)
        );

        OAuth.OAuthToken oAuthToken = apiClient.requestJWTUserToken (
                DSConfig.CLIENT_ID,
                DSConfig.IMPERSONATED_USER_GUID,
                scopes,
                privateKeyBytes,
                TOKEN_EXPIRATION_IN_SECONDS);
        apiClient.setAccessToken(oAuthToken.getAccessToken(), oAuthToken.getExpiresIn());
        System.out.println("Done. Continuing...\n");

//        System.out.println(apiClient.generateAccessToken(DSConfig.CLIENT_ID, privateKey, "eyJ0eXAiOiJNVCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiNjgxODVmZjEtNGU1MS00Y2U5LWFmMWMtNjg5ODEyMjAzMzE3In0.AQkAAAABAAYABwAAl9Dsb2bWSAgAACNXNHBm1kgCAEhUkmY-4NNLsGnNocdTok0VAAEAAAAYAAIAAAAFAAAAHQAAAA0AJAAAADhjZTI5Njc5LTYyYjItNDY5Mi1hYjNiLTEwZDg1NTA4ZDFlOTAAAJfQ7G9m1kgSAAEAAAALAAAAaW50ZXJhY3RpdmU.FtNP4Q-HedYYKGX7YfRkTUr1zE6TpAx6wP87D2nRCFzUyJGefP8xHs7-Pob_p3a4WDDWTfWdKE6VyEYhRWV3dUdXRVYbder6eBBf4uOpJ1IRGNrgv3YN-UWkPl76trTMTZLoyacrQ38zslhNoTWnsXQo6Gdjt-7z0KCAl46x8F1jSOludR9uqupnrsp42-gZXrzLy8dbE-LXfaMDeuc4ullQEMpgtkfaZhvl_xvv9FXGZsxYcwPtJhKE_TFRySZLHDNU7YPjbMNzZjfbKHx0kW5ucIwL-ZViFh1cQP_bb4x0aHKaQw-tvJRLKIH_3wEiqDh8_h4wwIR8gIzmYFkWSw"));
        System.out.println("access token: "+ apiClient.getAccessToken());

        if(_account == null)
            _account = this.getAccountInfo(apiClient);
        // default or configured account id.
        apiClient.setBasePath(_account.getBaseUri() + "/restapi");

        _token = apiClient.getAccessToken();
        expiresIn = System.currentTimeMillis() + (oAuthToken.getExpiresIn() * 1000);
    }

    private OAuth.Account getAccountInfo(ApiClient client) throws ApiException {
        OAuth.UserInfo userInfo = client.getUserInfo(client.getAccessToken());
        OAuth.Account accountInfo = null;

        if(DSConfig.TARGET_ACCOUNT_ID == null || DSConfig.TARGET_ACCOUNT_ID.length() == 0){
            List<OAuth.Account> accounts = userInfo.getAccounts();

            OAuth.Account acct = this.find(accounts, new ICondition<OAuth.Account>() {
                public boolean test(OAuth.Account member) {
                    return (member.getIsDefault() == "true");
                }
            });

            if (acct != null) return acct;

            acct = this.find(accounts, new ICondition<OAuth.Account>() {
                public boolean test(OAuth.Account member) {
                    return (member.getAccountId() == DSConfig.TARGET_ACCOUNT_ID);
                }
            });

            if (acct != null) return acct;

        }

        return accountInfo;
    }

    private OAuth.Account find(List<OAuth.Account> accounts, ICondition<OAuth.Account> criteria) {
        for (OAuth.Account acct: accounts) {
            if(criteria.test(acct)){
                return acct;
            }
        }
        return null;
    }

    interface ICondition<T> {
        boolean test(T member);
    }
}
