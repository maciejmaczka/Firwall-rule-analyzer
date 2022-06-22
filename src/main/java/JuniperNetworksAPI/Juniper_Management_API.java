/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JuniperNetworksAPI;
import General.Log;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.util.Base64;
/**
 *
 * @author jarek
 */
public class Juniper_Management_API {
    
       Log log_handler;

       String Mgmt_API_Server_IP = "10.9.0.30";
       String Mgmt_API_Server_Port = "4443";
       String Mgmt_API_Server_User = "apiadmin";
       String Mgmt_API_Server_Password = "Clico123!";
       String Mgmt_Login = "";
       String User_Agent = "Black-Wall-SI";

       boolean Mgmt_API_Server_Ignore_Cert = true;

       String Mgmt_API_Server_Auth_Token  = "";
       
       HttpClient API_Client;
       HttpHost MGMT_Server;

public void set_connection_paramters(String Management_IP, String Management_Port, String Username, char[] Password, boolean Igore_Cert) throws UnsupportedEncodingException
    {
        
        Mgmt_API_Server_IP = Management_IP;
        Mgmt_API_Server_Port = Management_Port;
        Mgmt_API_Server_User = Username;
        
        Mgmt_API_Server_Password  = new String(Password);
        Mgmt_API_Server_Ignore_Cert = Igore_Cert;
        
        Mgmt_Login = Base64.getEncoder().encodeToString((Mgmt_API_Server_User + ":" + Mgmt_API_Server_Password).getBytes("UTF-8"));
        
    }


public void API_Login()
        {

         

            try
            {         
                
                // just message
                
              //  log_handler.log_in_gui("Connecting to https://" + Mgmt_API_Server_IP + ":" + Mgmt_API_Server_Port + "\n");
                log_handler.refresh_log_area();

                 
                
                //
                // ignore certyficates 
                //
                
                if (Mgmt_API_Server_Ignore_Cert)
                {
                    TrustManager[] trustAllCerts = new TrustManager[] { 
                        new X509TrustManager() {     
                            public java.security.cert.X509Certificate[] getAcceptedIssuers() { 
                                return new X509Certificate[0];
                            } 
                            public void checkClientTrusted( 
                                java.security.cert.X509Certificate[] certs, String authType) {
                                } 
                            public void checkServerTrusted( 
                                java.security.cert.X509Certificate[] certs, String authType) {
                            }
                        } 
                    }; 
                 
                    SSLContext sc = SSLContext.getInstance("SSL"); 
                    sc.init(null, trustAllCerts, new java.security.SecureRandom()); 
                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());


                    // API CLIENT for untruset certs
                    
                    API_Client = HttpClientBuilder.create().setSSLContext(sc).build();
                    
                }
                else
                {
                    // API CLIENT for trusted certs
                    
                    API_Client = HttpClientBuilder.create().build();
                    
                }
                 


                //
                // Login header and body
                //

                
                HttpHost API_Server = new HttpHost(Mgmt_API_Server_IP,  Integer.parseInt(Mgmt_API_Server_Port), "https");    
                HttpPost API_Post_Call = new HttpPost("/rpc");
                API_Post_Call.addHeader("Accept", "application/json");
                API_Post_Call.addHeader("ContentType", "application/xml");
                API_Post_Call.addHeader("User-Agent", User_Agent);
                API_Post_Call.addHeader("Authorization","Basic " + Mgmt_Login);
                
               /**
                Map<String,String> API_Body = new HashMap<String,String>();
                API_Body.put("user", Mgmt_API_Server_User);
                API_Body.put("password", Mgmt_API_Server_Password);
                API_Body.put("continue-last-session", "true");
                API_Body.put("session-name", User_Agent);
                API_Body.put("session-timeout", "3600");
               
                
               
               
                
                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();
                
            
                
                StringEntity Post_Body = new StringEntity(body_string);
                API_Post_Call.setEntity(Post_Body); 
                **/
             
               //
               // execute query
               //
               
               HttpResponse API_Response = API_Client.execute(API_Server, API_Post_Call);
               int HttpResponseStatus = API_Response.getStatusLine().getStatusCode();
               
               String response_string = EntityUtils.toString(API_Response.getEntity());
               
             //  log_handler.log_in_gui("HTTP Status: " + String.valueOf(HttpResponseStatus) + "\n");
               
            
               //Temporary!!!
               //log_handler.log_in_gui(response_string );
                          
         
                //
                // Get the response
                //


                
              //  boolean logon_success = Mgmt_API_Connection_Login_Parser(HttpResponseStatus);

                if (HttpResponseStatus == 200)
                {
                    
                //    log_handler.log_in_gui("Authentication succeeded \n" );

                }
                else
                {

                //    log_handler.log_in_gui("Authentication failed \n");

                }

                



            }

            catch (Exception e)
            {

                //
                // Something went wrong
                // Multi exception handler
                //


             //   log_handler.log_in_gui("Connection failed: \n" + e.getLocalizedMessage());
                log_handler.log_in_file("(AL) Error: " + e.getLocalizedMessage());
                
                return;
            }






        }

 public void merge_log_handler(Log log_handler)
    {
        
        this.log_handler = log_handler;
        
        
    }
    
 private boolean Mgmt_API_Connection_Login_Parser(String responseString)
        {

            //
            //
            // GET SID TOKEN
            //
            //
            
           
            
           try
           {
            
                Object rss_parser = new JSONParser().parse(responseString);     
                JSONObject rss = (JSONObject) rss_parser; 

        
            
                Mgmt_API_Server_Auth_Token = (String)rss.get("boundary");

                if (Mgmt_API_Server_Auth_Token == null)
                {

                    
                    return false;
                }

                
                return true;
                
           }  
           catch (Exception e)
           {
               
//                log_handler.log_in_gui("Error: \n" + e.getLocalizedMessage());
                log_handler.log_in_file("(AL) Error: " + e.getLocalizedMessage());
                return false;
           }

            
        }




}
